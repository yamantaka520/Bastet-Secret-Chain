//! `bsc` — the one binary (ADR 0001).
//!
//! ```text
//! bsc init   --vault PATH            create a vault (passphrase prompted)
//! bsc serve  --vault PATH [--bind]   run the daemon, sealed, on loopback
//! bsc mcp    [--url] [--token-file]  MCP stdio server; token from file or BSC_TOKEN
//! bsc audit  --vault PATH            verify the ledger offline
//! bsc service install|uninstall|status [--vault] [--bind] [--dry-run]
//! bsc doctor [--vault] [--url]        checklist: file, ledger, daemon, UI, auto-start, clock
//! ```

#![forbid(unsafe_code)]

mod doctor;
mod service;

use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

use bsc_store::{audit::ChainStatus, Actor, Vault};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "bsc", version, about = "Bastet Secret Chain")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault file. Prompts for a passphrase twice.
    Init {
        /// Where to create the vault.
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        /// Read the passphrase from the first line of stdin instead of the
        /// terminal. For scripts and tests; no confirmation prompt.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Run the daemon. The vault starts sealed; unseal from the UI or API.
    Serve {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        /// Loopback only; remote clients reach the daemon through a reverse proxy.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
        /// Acknowledge that a TLS reverse proxy fronts this daemon at this
        /// origin (e.g. https://sec.example). Accepts that Origin, marks the
        /// session cookie Secure, throttles logins per forwarded client
        /// address, and writes exposure_acknowledged to the ledger.
        #[arg(long)]
        public_origin: Option<String>,
        /// Unseal at startup from a systemd encrypted credential of this name
        /// (`LoadCredentialEncrypted=<name>:…` in the unit; the file appears at
        /// `$CREDENTIALS_DIRECTORY/<name>`). Opt-in unattended unseal for
        /// servers. Recorded in the ledger as `unseal_unattended`.
        #[arg(long, conflicts_with = "unseal_keychain")]
        unseal_credential: Option<String>,
        /// Unseal at startup from the macOS Keychain generic-password item with
        /// this service name (`security add-generic-password -s <name> -a bsc
        /// -w`). Opt-in unattended unseal for a workstation LaunchAgent.
        #[arg(long)]
        unseal_keychain: Option<String>,
        /// Telegram approval channel: systemd credential name holding the bot
        /// token (`LoadCredentialEncrypted=telegram-token:…`).
        #[arg(long, conflicts_with = "telegram_token_file")]
        telegram_token_credential: Option<String>,
        /// Telegram approval channel: 0600 file holding the bot token.
        #[arg(long)]
        telegram_token_file: Option<PathBuf>,
        /// The one Telegram chat id whose Approve/Deny buttons are honoured.
        #[arg(long)]
        telegram_chat: Option<i64>,
        /// Telegram user ids allowed to decide (repeatable). Empty = anyone in the chat.
        #[arg(long = "telegram-user")]
        telegram_users: Vec<i64>,
        /// Bot API base (tests only).
        #[arg(long, default_value = "https://api.telegram.org", hide = true)]
        telegram_api_base: String,
    },
    /// Serve MCP over stdio as a client of a running daemon.
    Mcp {
        #[arg(long, default_value = "http://127.0.0.1:8787")]
        url: String,
        /// File containing the bsct_ token. Otherwise BSC_TOKEN is read.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Verify the audit chain of a vault file, sealed. With --anchor-file, also
    /// check the chain against every anchor in that file (detects tail
    /// truncation) and, if consistent, append a fresh anchor.
    Audit {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        /// Append-only JSON-lines file of anchors, kept somewhere the vault
        /// file's owner cannot silently rewrite (another disk, a log shipper,
        /// a git repo). Default: none.
        #[arg(long)]
        anchor_file: Option<PathBuf>,
        /// Only check anchors; do not append a new one.
        #[arg(long)]
        no_anchor: bool,
    },
    /// Break-glass export: every item and every version, sealed under a
    /// separate export passphrase. Prompts for the vault passphrase, then the
    /// export passphrase twice. With --passphrase-stdin, reads them as lines.
    Export {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        /// Output file (created 0600). Never write it next to the vault.
        #[arg(long)]
        out: PathBuf,
        /// Read vault passphrase then export passphrase from stdin (scripts, tests).
        #[arg(long)]
        passphrase_stdin: bool,
        /// Reason recorded in the ledger.
        #[arg(long, default_value = "break-glass export")]
        reason: String,
    },
    /// Import a bundle made by `export` into this vault as new items.
    Import {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        #[arg(long = "in", value_name = "FILE")]
        input: PathBuf,
        /// Read vault passphrase then export passphrase from stdin.
        #[arg(long)]
        passphrase_stdin: bool,
        #[arg(long, default_value = "restore from export")]
        reason: String,
    },
    /// Start the daemon at login through launchd, systemd --user, or Task Scheduler.
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Check the installation and print a ✅/⚠️/❌ checklist.
    Doctor {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8787")]
        url: String,
        /// Bind the auto-start check assumes, if a service is installed.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Write the definition and start the daemon now and at every login.
    Install {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        /// Reverse-proxy origin to bake into the service definition.
        #[arg(long)]
        public_origin: Option<String>,
        /// Print the definition and the commands without touching the system.
        #[arg(long)]
        dry_run: bool,
    },
    /// Stop the daemon and remove the definition. The vault is untouched.
    Uninstall {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Ask the supervisor what it knows about the daemon.
    Status {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
}

fn default_vault() -> PathBuf {
    let base = std::env::var_os("BSC_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".bsc")))
        .unwrap_or_else(|| PathBuf::from(".bsc"));
    base.join("vault.bsc")
}

/// Opt-in unattended unseal. Returns the source label on success, `None` when
/// neither option was given. A configured source that fails is an error —
/// starting sealed and silently waiting would hide a broken deployment.
fn unattended_unseal(
    v: &mut Vault,
    credential: Option<&str>,
    keychain: Option<&str>,
) -> Result<Option<String>, String> {
    let (pw, source): (Zeroizing<Vec<u8>>, &str) = if let Some(name) = credential {
        let dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(
            "--unseal-credential given but CREDENTIALS_DIRECTORY is not set; is this running under systemd with LoadCredential(Encrypted)?",
        )?;
        let path = PathBuf::from(dir).join(name);
        let bytes =
            std::fs::read(&path).map_err(|e| format!("credential {}: {e}", path.display()))?;
        (Zeroizing::new(trim_newline(bytes)), "systemd-credential")
    } else if let Some(service) = keychain {
        if !cfg!(target_os = "macos") {
            return Err("--unseal-keychain is only available on macOS".into());
        }
        let out = std::process::Command::new("security")
            .args(["find-generic-password", "-s", service, "-a", "bsc", "-w"])
            .output()
            .map_err(|e| format!("security: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "keychain item {service:?} (account bsc) not found or not readable: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        (Zeroizing::new(trim_newline(out.stdout)), "macos-keychain")
    } else {
        return Ok(None);
    };
    if pw.is_empty() {
        return Err(format!(
            "unattended unseal source {source} yielded an empty passphrase"
        ));
    }
    v.unseal_unattended(&pw, source)
        .map_err(|e| format!("unattended unseal from {source} failed: {e}"))?;
    tracing::warn!(source, "vault unsealed unattended at startup");
    Ok(Some(source.to_string()))
}

thread_local! {
    static TELEGRAM_TASK: std::cell::RefCell<Option<(std::sync::Arc<bsc_daemon::telegram::Telegram>, tokio::sync::mpsc::UnboundedReceiver<bsc_daemon::notify::Escalation>)>> = const { std::cell::RefCell::new(None) };
}

/// Build the Telegram channel config from the CLI, or `None` when not asked
/// for. Token and chat must come together; a token source that cannot be
/// read is an error, not a silent fallback.
fn telegram_config(
    credential: Option<&str>,
    file: Option<&std::path::Path>,
    chat: Option<i64>,
    users: &[i64],
    api_base: &str,
) -> Result<Option<bsc_daemon::telegram::TelegramConfig>, String> {
    let token: Zeroizing<String> = match (credential, file) {
        (None, None) => {
            if chat.is_some() {
                return Err(
                    "--telegram-chat needs --telegram-token-credential or --telegram-token-file"
                        .into(),
                );
            }
            return Ok(None);
        }
        (Some(name), None) => {
            let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
                .ok_or("--telegram-token-credential given but CREDENTIALS_DIRECTORY is not set")?;
            let bytes = std::fs::read(PathBuf::from(dir).join(name))
                .map_err(|e| format!("telegram credential {name}: {e}"))?;
            Zeroizing::new(
                String::from_utf8(trim_newline(bytes))
                    .map_err(|_| "telegram token is not UTF-8")?,
            )
        }
        (None, Some(p)) => {
            let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            Zeroizing::new(
                String::from_utf8(trim_newline(bytes))
                    .map_err(|_| "telegram token is not UTF-8")?,
            )
        }
        (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
    };
    let chat_id = chat.ok_or("telegram token given but --telegram-chat is missing")?;
    if token.is_empty() || !token.contains(':') {
        return Err("telegram token does not look like a bot token".into());
    }
    Ok(Some(bsc_daemon::telegram::TelegramConfig {
        api_base: api_base.to_string(),
        token: std::sync::Arc::new(token),
        chat_id,
        allowed_users: users.to_vec(),
        external_step: 3,
    }))
}

fn read_anchors(path: &std::path::Path) -> Result<Vec<bsc_store::audit::Anchor>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l).map_err(|e| format!("{} line {}: {e}", path.display(), i + 1))
        })
        .collect()
}

fn append_anchor(path: &std::path::Path, a: &bsc_store::audit::Anchor) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    writeln!(
        f,
        "{}",
        serde_json::to_string(a).map_err(|e| e.to_string())?
    )
    .map_err(|e| e.to_string())
}

/// Two passphrases, from stdin lines (scripts/tests) or interactive prompts.
fn two_passphrases(
    from_stdin: bool,
    first: &str,
    second: &str,
) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
    if from_stdin {
        let mut a = String::new();
        let mut b = String::new();
        std::io::stdin()
            .read_line(&mut a)
            .map_err(|e| e.to_string())?;
        std::io::stdin()
            .read_line(&mut b)
            .map_err(|e| e.to_string())?;
        let a = Zeroizing::new(a.trim_end_matches(['\r', '\n']).to_string());
        let b = Zeroizing::new(b.trim_end_matches(['\r', '\n']).to_string());
        if a.is_empty() || b.is_empty() {
            return Err("two non-empty passphrase lines are required on stdin".into());
        }
        return Ok((a, b));
    }
    let a = Zeroizing::new(rpassword::prompt_password(first).map_err(|e| e.to_string())?);
    let b = Zeroizing::new(rpassword::prompt_password(second).map_err(|e| e.to_string())?);
    let b2 = Zeroizing::new(rpassword::prompt_password("Again: ").map_err(|e| e.to_string())?);
    if *b != *b2 {
        return Err("export passphrases do not match".into());
    }
    Ok((a, b))
}

fn trim_newline(mut b: Vec<u8>) -> Vec<u8> {
    while matches!(b.last(), Some(b'\n' | b'\r')) {
        b.pop();
    }
    b
}

fn prompt_passphrase(confirm: bool) -> Result<Zeroizing<String>, String> {
    let first = Zeroizing::new(
        rpassword::prompt_password("Vault passphrase: ").map_err(|e| e.to_string())?,
    );
    if first.is_empty() {
        return Err("empty passphrase".into());
    }
    if confirm {
        let second =
            Zeroizing::new(rpassword::prompt_password("Again: ").map_err(|e| e.to_string())?);
        if *first != *second {
            return Err("passphrases do not match".into());
        }
    }
    Ok(first)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bsc: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init {
            vault,
            passphrase_stdin,
        } => {
            if let Some(dir) = vault.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
                }
            }
            let pw = if passphrase_stdin {
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|e| e.to_string())?;
                let pw = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string());
                if pw.is_empty() {
                    return Err("empty passphrase on stdin".into());
                }
                pw
            } else {
                prompt_passphrase(true)?
            };
            let v = Vault::create(&vault, pw.as_bytes()).map_err(|e| e.to_string())?;
            let p = v.kdf_params();
            eprintln!(
                "created {} (Argon2id {} MiB / {} passes / {} lanes). Keep the passphrase; there is no recovery.",
                vault.display(),
                p.m_cost_kib / 1024,
                p.t_cost,
                p.p_cost
            );
            Ok(())
        }
        Cmd::Serve {
            vault,
            bind,
            public_origin,
            unseal_credential,
            unseal_keychain,
            telegram_token_credential,
            telegram_token_file,
            telegram_chat,
            telegram_users,
            telegram_api_base,
        } => {
            let mut v = Vault::open(&vault).map_err(|e| format!("{}: {e}", vault.display()))?;
            let unattended = unattended_unseal(
                &mut v,
                unseal_credential.as_deref(),
                unseal_keychain.as_deref(),
            )?;
            if let Some(o) = &public_origin {
                let bare = o.trim_end_matches('/');
                let scheme_ok = bare.starts_with("https://") || bare.starts_with("http://");
                if !scheme_ok || bare.matches('/').count() != 2 {
                    return Err(format!(
                        "--public-origin must be scheme://host[:port] with no path, got {o:?}"
                    ));
                }
                if bare.starts_with("http://") {
                    eprintln!("warning: --public-origin is plain http; the session cookie will not be Secure and passphrases cross the network unencrypted unless the proxy terminates TLS");
                }
            }
            let ui_url = public_origin
                .clone()
                .map(|o| format!("{}/", o.trim_end_matches('/')))
                .unwrap_or_else(|| format!("http://{bind}/"));
            let os_notifier: std::sync::Arc<dyn bsc_daemon::notify::Notifier> =
                std::sync::Arc::new(bsc_daemon::notify::OsNotifier { ui_url });
            let telegram = telegram_config(
                telegram_token_credential.as_deref(),
                telegram_token_file.as_deref(),
                telegram_chat,
                &telegram_users,
                &telegram_api_base,
            )?;
            let (notifier, telegram_rx): (
                std::sync::Arc<dyn bsc_daemon::notify::Notifier>,
                Option<_>,
            ) = if telegram.is_some() {
                let (n, rx) = bsc_daemon::notify::ChannelNotifier::new(os_notifier);
                (n, Some(rx))
            } else {
                (os_notifier, None)
            };
            let config = bsc_daemon::Config {
                public_origin: public_origin.map(|o| o.trim_end_matches('/').to_string()),
                unattended_unseal: unattended,
                ..bsc_daemon::Config::default()
            };
            let state = bsc_daemon::AppState::new_with_notifier(v, config, notifier);
            if let (Some(cfg), Some(rx)) = (telegram, telegram_rx) {
                tracing::warn!(
                    chat_id = cfg.chat_id,
                    "telegram approval channel enabled (outbound only)"
                );
                let tg =
                    std::sync::Arc::new(bsc_daemon::telegram::Telegram::new(cfg, state.clone()));
                let rt_handle_tg = tg.clone();
                // Spawned inside the runtime below.
                TELEGRAM_TASK.with(|c| *c.borrow_mut() = Some((rt_handle_tg, rx)));
            }
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(async move {
                if let Some((tg, rx)) = TELEGRAM_TASK.with(|c| c.borrow_mut().take()) {
                    tokio::spawn(tg.run(rx));
                }
                let shutdown = async {
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("shutting down");
                };
                bsc_daemon::serve(state, bind, shutdown).await
            })
            .map_err(|e| e.to_string())
        }
        Cmd::Mcp { url, token_file } => {
            let token = match token_file {
                Some(p) => Zeroizing::new(
                    std::fs::read_to_string(&p)
                        .map_err(|e| format!("{}: {e}", p.display()))?
                        .trim()
                        .to_string(),
                ),
                None => Zeroizing::new(
                    std::env::var("BSC_TOKEN").map_err(|_| "set BSC_TOKEN or pass --token-file")?,
                ),
            };
            if !token.starts_with("bsct_") {
                return Err("token does not look like a bsct_ value".into());
            }
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(bsc_mcp::McpServer::new(url, token.as_str()).run_stdio())
                .map_err(|e| e.to_string())
        }
        Cmd::Export {
            vault,
            out,
            passphrase_stdin,
            reason,
        } => {
            let mut v = Vault::open(&vault).map_err(|e| format!("{}: {e}", vault.display()))?;
            let (vault_pw, export_pw) = two_passphrases(
                passphrase_stdin,
                "Vault passphrase: ",
                "Export passphrase (different from the vault's): ",
            )?;
            if vault_pw == export_pw {
                return Err("the export passphrase must differ from the vault passphrase".into());
            }
            v.unseal(
                vault_pw.as_bytes(),
                &Actor::Human {
                    session: "cli-export".into(),
                },
            )
            .map_err(|e| e.to_string())?;
            let actor = Actor::Human {
                session: "cli-export".into(),
            };
            let bundle = v.export_all(&actor, &reason).map_err(|e| e.to_string())?;
            let params = bsc_crypto::kdf::KdfParams::recommended_like(v.kdf_params())
                .map_err(|e| e.to_string())?;
            let bytes = bsc_store::export::seal(&bundle, export_pw.as_bytes(), &params)
                .map_err(|e| e.to_string())?;
            if out.exists() {
                return Err(format!("{} exists; refusing to overwrite", out.display()));
            }
            std::fs::write(&out, &bytes).map_err(|e| format!("{}: {e}", out.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
            }
            eprintln!(
                "exported {} items ({} bytes) to {} — sealed under the export passphrase; keep them apart",
                bundle.items.len(),
                bytes.len(),
                out.display()
            );
            Ok(())
        }
        Cmd::Import {
            vault,
            input,
            passphrase_stdin,
            reason,
        } => {
            let mut v = Vault::open(&vault).map_err(|e| format!("{}: {e}", vault.display()))?;
            let (vault_pw, export_pw) = two_passphrases(
                passphrase_stdin,
                "Vault passphrase: ",
                "Export passphrase: ",
            )?;
            v.unseal(
                vault_pw.as_bytes(),
                &Actor::Human {
                    session: "cli-import".into(),
                },
            )
            .map_err(|e| e.to_string())?;
            let bytes = std::fs::read(&input).map_err(|e| format!("{}: {e}", input.display()))?;
            let bundle = bsc_store::export::open(&bytes, export_pw.as_bytes())
                .map_err(|e| format!("cannot open bundle: {e}"))?;
            let actor = Actor::Human {
                session: "cli-import".into(),
            };
            let ids = v
                .import_all(&bundle, &actor, &reason)
                .map_err(|e| e.to_string())?;
            eprintln!(
                "imported {} items (exported {} from chain head {}…)",
                ids.len(),
                bundle.exported_at,
                &bundle.source_head[..12.min(bundle.source_head.len())]
            );
            for id in ids {
                println!("{id}");
            }
            Ok(())
        }
        Cmd::Service { action } => match action {
            ServiceCmd::Install {
                vault,
                bind,
                public_origin,
                dry_run,
            } => {
                let spec = service::spec_for_current(&vault, &bind, public_origin.as_deref())?;
                print!("{}", service::install(&spec, dry_run)?);
                Ok(())
            }
            ServiceCmd::Uninstall {
                vault,
                bind,
                dry_run,
            } => {
                let spec = service::spec_for_current(&vault, &bind, None)?;
                print!("{}", service::uninstall(&spec, dry_run)?);
                Ok(())
            }
            ServiceCmd::Status { vault, bind } => {
                let spec = service::spec_for_current(&vault, &bind, None)?;
                print!("{}", service::status(&spec)?);
                Ok(())
            }
        },
        Cmd::Doctor { vault, url, bind } => {
            let spec = service::spec_for_current(&vault, &bind, None).ok();
            let report = doctor::run(&vault, url.trim_end_matches('/'), spec.as_ref());
            print!("{report}");
            match report.worst() {
                doctor::Level::Fail => Err("one or more checks failed".into()),
                _ => Ok(()),
            }
        }
        Cmd::Audit {
            vault,
            anchor_file,
            no_anchor,
        } => {
            let v = Vault::open(&vault).map_err(|e| format!("{}: {e}", vault.display()))?;
            let (len, head) = match v.audit_verify().map_err(|e| e.to_string())? {
                ChainStatus::Intact { len, head } => (len, head),
                ChainStatus::Broken { at } => {
                    return Err(format!("audit chain broken at record {at}"))
                }
            };
            println!("intact: {len} records, head {}", hex::encode(head));
            if let Some(path) = anchor_file {
                let anchors = read_anchors(&path)?;
                match v.audit_check_anchors(&anchors).map_err(|e| e.to_string())? {
                    bsc_store::audit::AnchorStatus::Consistent { anchors: n } => {
                        println!("anchors: {n} checked, consistent");
                    }
                    bsc_store::audit::AnchorStatus::Truncated {
                        anchored_len,
                        actual_len,
                    } => {
                        return Err(format!(
                            "TAIL TRUNCATED: an anchor recorded {anchored_len} records, the chain now has {actual_len}"
                        ));
                    }
                    bsc_store::audit::AnchorStatus::Diverged { at } => {
                        return Err(format!(
                            "HISTORY REWRITTEN: record {at} no longer matches its anchor"
                        ));
                    }
                }
                if !no_anchor {
                    let a = v.audit_anchor().map_err(|e| e.to_string())?;
                    append_anchor(&path, &a)?;
                    println!(
                        "anchored: len {} head {}… → {}",
                        a.len,
                        &a.head[..12],
                        path.display()
                    );
                }
            }
            Ok(())
        }
    }
}
