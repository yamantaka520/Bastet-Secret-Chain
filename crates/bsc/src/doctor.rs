//! `bsc doctor`: a checklist an operator can read at a glance. Each check is
//! ✅ / ⚠️ / ❌; the exit code is non-zero only for ❌. Nothing here reads a
//! secret or needs the vault unsealed.

use std::{fmt, path::Path, time::Duration};

use bsc_store::{audit::ChainStatus, Vault};

use crate::service::{self, Spec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

pub struct Check {
    pub level: Level,
    pub name: &'static str,
    pub detail: String,
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mark = match self.level {
            Level::Ok => "✅",
            Level::Warn => "⚠️ ",
            Level::Fail => "❌",
        };
        write!(f, "{mark} {:<14} {}", self.name, self.detail)
    }
}

fn ok(name: &'static str, d: impl Into<String>) -> Check {
    Check {
        level: Level::Ok,
        name,
        detail: d.into(),
    }
}
fn warn(name: &'static str, d: impl Into<String>) -> Check {
    Check {
        level: Level::Warn,
        name,
        detail: d.into(),
    }
}
fn fail(name: &'static str, d: impl Into<String>) -> Check {
    Check {
        level: Level::Fail,
        name,
        detail: d.into(),
    }
}

pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn worst(&self) -> Level {
        if self.checks.iter().any(|c| c.level == Level::Fail) {
            Level::Fail
        } else if self.checks.iter().any(|c| c.level == Level::Warn) {
            Level::Warn
        } else {
            Level::Ok
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            writeln!(f, "{c}")?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn mode(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

pub fn run(vault: &Path, url: &str, spec: Option<&Spec>) -> Report {
    let mut c = Vec::new();

    // 1. Vault file and permissions.
    if vault.exists() {
        c.push(ok("vault", format!("{}", vault.display())));
        #[cfg(unix)]
        {
            match mode(vault) {
                Some(0o600) => c.push(ok("permissions", "vault 0600")),
                Some(m) => c.push(fail(
                    "permissions",
                    format!(
                        "vault is {m:o}; expected 0600 — run: chmod 600 {}",
                        vault.display()
                    ),
                )),
                None => c.push(warn("permissions", "could not read vault mode")),
            }
            if let Some(dir) = vault.parent() {
                match mode(dir) {
                    Some(0o700) => c.push(ok("directory", format!("{} 0700", dir.display()))),
                    Some(m) => c.push(warn(
                        "directory",
                        format!("{} is {m:o}; 0700 recommended", dir.display()),
                    )),
                    None => {}
                }
            }
        }
        // 2. Header and ledger, sealed.
        match Vault::open(vault) {
            Ok(v) => {
                let p = v.kdf_params();
                c.push(ok(
                    "format",
                    format!(
                        "bsc/1 · Argon2id {} MiB · t={} · p={}",
                        p.m_cost_kib / 1024,
                        p.t_cost,
                        p.p_cost
                    ),
                ));
                match v.audit_verify() {
                    Ok(ChainStatus::Intact { len, head }) => c.push(ok(
                        "audit chain",
                        format!("intact, {len} records, head {}…", hex::encode(&head[..6])),
                    )),
                    Ok(ChainStatus::Broken { at }) => c.push(fail(
                        "audit chain",
                        format!("BROKEN at record {at} — the ledger was edited"),
                    )),
                    Err(e) => c.push(fail("audit chain", format!("could not verify: {e}"))),
                }
            }
            Err(e) => c.push(fail("format", format!("cannot open vault: {e}"))),
        }
        // 3. Directory writable.
        if let Some(dir) = vault.parent() {
            let probe = dir.join(".bsc-doctor-probe");
            match std::fs::write(&probe, b"x").and_then(|_| std::fs::remove_file(&probe)) {
                Ok(()) => c.push(ok("writable", format!("{}", dir.display()))),
                Err(e) => c.push(fail("writable", format!("{}: {e}", dir.display()))),
            }
        }
    } else {
        c.push(fail(
            "vault",
            format!("{} does not exist — run `bsc init`", vault.display()),
        ));
    }

    // 4. Daemon reachability and bind.
    let loopback = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .map(|h| h.starts_with("127.0.0.1") || h.starts_with("localhost") || h.starts_with("[::1]"))
        .unwrap_or(false);
    if loopback {
        c.push(ok("bind", format!("{url} is loopback")));
    } else {
        c.push(fail(
            "bind",
            format!("{url} is not loopback; remote exposure is not implemented"),
        ));
    }
    let rt = tokio::runtime::Runtime::new().ok();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok();
    match (rt.as_ref(), http.as_ref()) {
        (Some(rt), Some(http)) => {
            let status = rt.block_on(async {
                let r = http
                    .get(format!("{url}/v1/vault/status"))
                    .send()
                    .await
                    .ok()?;
                let v: serde_json::Value = r.json().await.ok()?;
                Some(v)
            });
            match status {
                Some(v) => {
                    let sealed = v["sealed"].as_bool().unwrap_or(true);
                    c.push(ok("daemon", format!("running v{} · {} · uptime {}s", v["version"].as_str().unwrap_or("?"), if sealed { "sealed" } else { "unsealed" }, v["uptime"])));
                    let ui = rt.block_on(async {
                        let r = http.get(format!("{url}/")).send().await.ok()?;
                        let csp = r.headers().contains_key("content-security-policy");
                        let body = r.text().await.ok()?;
                        Some((csp, body.contains("id=\"root\"")))
                    });
                    match ui {
                        Some((true, true)) => c.push(ok("web ui", format!("served at {url}/ with CSP"))),
                        Some((_, false)) => c.push(warn("web ui", "daemon serves a placeholder: the UI was not built into this binary")),
                        Some((false, true)) => c.push(warn("web ui", "served without a Content-Security-Policy header")),
                        None => c.push(warn("web ui", "could not fetch /")),
                    }
                }
                None => c.push(warn("daemon", format!("not reachable at {url} — start it with `bsc serve` or `bsc service install`"))),
            }
        }
        _ => c.push(warn("daemon", "could not build an HTTP client")),
    }

    // 5. Service definition.
    match spec {
        Some(s) => {
            if service::is_installed(s) {
                c.push(ok(
                    "auto-start",
                    match s.os {
                        service::Os::Macos => format!("LaunchAgent {} present", service::LABEL),
                        service::Os::Linux => {
                            format!("systemd user unit {} present", service::UNIT)
                        }
                        service::Os::Windows => {
                            format!("scheduled task \"{}\" present", service::TASK)
                        }
                    },
                ));
                if s.os == service::Os::Linux {
                    let linger = std::process::Command::new("loginctl")
                        .args(["show-user", "--property=Linger"])
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Linger=yes"))
                        .unwrap_or(false);
                    if !linger {
                        c.push(warn("linger", "user services stop at logout; run `loginctl enable-linger` to keep the daemon up"));
                    }
                }
            } else {
                c.push(warn(
                    "auto-start",
                    "not installed — `bsc service install` starts the daemon at login",
                ));
            }
        }
        None => c.push(warn("auto-start", "unsupported platform")),
    }

    // 6. Notification tool.
    let tool = if cfg!(target_os = "macos") {
        "osascript"
    } else if cfg!(target_os = "linux") {
        "notify-send"
    } else {
        "powershell"
    };
    let found = which(tool);
    c.push(if found {
        ok(
            "notifications",
            format!("{tool} available for approval alerts"),
        )
    } else {
        warn(
            "notifications",
            format!("{tool} not found; approval escalations will only be logged"),
        )
    });

    // 7. Clock sanity — tokens, sessions, and Argon2 parameters all trust it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if now > 1_767_225_600 {
        c.push(ok("clock", format!("unix {now}")));
    } else {
        c.push(fail(
            "clock",
            format!("system time {now} is before 2026; token expiry and approvals will misbehave"),
        ));
    }

    Report { checks: c }
}

fn which(bin: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|d| {
        let p = d.join(bin);
        p.exists() || d.join(format!("{bin}.exe")).exists()
    })
}
