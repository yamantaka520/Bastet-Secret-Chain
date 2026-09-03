//! `bsc` — the one binary (ADR 0001).
//!
//! ```text
//! bsc init   --vault PATH            create a vault (passphrase prompted)
//! bsc serve  --vault PATH [--bind]   run the daemon, sealed, on loopback
//! bsc mcp    [--url] [--token-file]  MCP stdio server; token from file or BSC_TOKEN
//! bsc audit  --vault PATH            verify the ledger offline
//! ```

#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

use bsc_store::{audit::ChainStatus, Vault};
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
        /// Loopback only until remote exposure is implemented.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
    },
    /// Serve MCP over stdio as a client of a running daemon.
    Mcp {
        #[arg(long, default_value = "http://127.0.0.1:8787")]
        url: String,
        /// File containing the bsct_ token. Otherwise BSC_TOKEN is read.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Verify the audit chain of a vault file, sealed.
    Audit {
        #[arg(long, default_value_os_t = default_vault())]
        vault: PathBuf,
    },
}

fn default_vault() -> PathBuf {
    let base = std::env::var_os("BSC_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".bsc")))
        .unwrap_or_else(|| PathBuf::from(".bsc"));
    base.join("vault.bsc")
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
        Cmd::Serve { vault, bind } => {
            let v = Vault::open(&vault).map_err(|e| format!("{}: {e}", vault.display()))?;
            let notifier = std::sync::Arc::new(bsc_daemon::notify::OsNotifier {
                ui_url: format!("http://{bind}/"),
            });
            let state =
                bsc_daemon::AppState::new_with_notifier(v, bsc_daemon::Config::default(), notifier);
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(async move {
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
        Cmd::Audit { vault } => {
            let v = Vault::open(&vault).map_err(|e| format!("{}: {e}", vault.display()))?;
            match v.audit_verify().map_err(|e| e.to_string())? {
                ChainStatus::Intact { len, head } => {
                    println!("intact: {len} records, head {}", hex::encode(head));
                    Ok(())
                }
                ChainStatus::Broken { at } => Err(format!("audit chain broken at record {at}")),
            }
        }
    }
}
