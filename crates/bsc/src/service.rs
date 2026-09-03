//! Boot auto-start through the platform's own supervisor, at user level, with
//! no elevation: a launchd LaunchAgent on macOS, a systemd user unit on Linux,
//! a Task Scheduler logon task on Windows. Every operation has a `--dry-run`
//! that prints the definition and the commands instead of executing them, and
//! the definitions are pure functions of their inputs so tests cover them on
//! every platform regardless of the host.

use std::{
    fmt,
    path::{Path, PathBuf},
    process::Command,
};

/// Target platform. Separate from `cfg!` so definitions can be tested
/// cross-platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Macos,
    Linux,
    Windows,
}

impl Os {
    pub fn current() -> Option<Os> {
        if cfg!(target_os = "macos") {
            Some(Os::Macos)
        } else if cfg!(target_os = "linux") {
            Some(Os::Linux)
        } else if cfg!(target_os = "windows") {
            Some(Os::Windows)
        } else {
            None
        }
    }
}

/// launchd label / systemd unit / scheduled task name.
pub const LABEL: &str = "io.bastet.bsc";
pub const UNIT: &str = "bsc";
pub const TASK: &str = "Bastet Secret Chain";

/// Everything a definition needs.
#[derive(Clone, Debug)]
pub struct Spec {
    pub os: Os,
    pub exe: PathBuf,
    pub vault: PathBuf,
    pub bind: String,
    pub home: PathBuf,
}

impl Spec {
    /// Where the definition file lives (Windows has none; the task is in the
    /// scheduler's own store).
    pub fn definition_path(&self) -> Option<PathBuf> {
        // Joined with '/' explicitly: these paths describe the *target* OS and
        // must not pick up the host's separator when generated or tested on
        // Windows.
        match self.os {
            Os::Macos => Some(unix_join(
                &self.home,
                &format!("Library/LaunchAgents/{LABEL}.plist"),
            )),
            Os::Linux => Some(unix_join(
                &self.home,
                &format!(".config/systemd/user/{UNIT}.service"),
            )),
            Os::Windows => None,
        }
    }

    pub fn log_dir(&self) -> PathBuf {
        match self.os {
            Os::Macos => unix_join(&self.home, "Library/Logs/bsc"),
            Os::Linux => unix_join(&self.home, ".bsc/logs"),
            Os::Windows => self.home.join(".bsc").join("logs"),
        }
    }

    /// The definition text (plist or unit). `None` on Windows.
    pub fn definition(&self) -> Option<String> {
        match self.os {
            Os::Macos => Some(self.plist()),
            Os::Linux => Some(self.unit()),
            Os::Windows => None,
        }
    }

    fn plist(&self) -> String {
        let x = xml_escape;
        let log = self.log_dir();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>serve</string>
    <string>--vault</string>
    <string>{vault}</string>
    <string>--bind</string>
    <string>{bind}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>2</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{out}</string>
  <key>StandardErrorPath</key><string>{err}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key><string>info</string>
    <key>HOME</key><string>{home}</string>
  </dict>
</dict>
</plist>
"#,
            exe = x(&self.exe.display().to_string()),
            vault = x(&self.vault.display().to_string()),
            bind = x(&self.bind),
            out = x(&unix_join(&log, "bsc.log").display().to_string()),
            err = x(&unix_join(&log, "bsc.err.log").display().to_string()),
            home = x(&self.home.display().to_string()),
        )
    }

    fn unit(&self) -> String {
        let vault_dir = self
            .vault
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        format!(
            r#"[Unit]
Description=Bastet Secret Chain vault daemon (loopback only)
Documentation=https://github.com/yamantaka520/Bastet-Secret-Chain
After=default.target

[Service]
Type=simple
ExecStart={exe} serve --vault {vault} --bind {bind}
Restart=on-failure
RestartSec=2
Environment=RUST_LOG=info
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
# The vault directory is the only place the daemon writes.
ReadWritePaths={vault_dir}

[Install]
WantedBy=default.target
"#,
            exe = systemd_quote(&self.exe.display().to_string()),
            vault = systemd_quote(&self.vault.display().to_string()),
            bind = self.bind,
        )
    }

    /// Commands `install` runs, in order, after writing the definition.
    pub fn install_commands(&self) -> Vec<Vec<String>> {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        match self.os {
            Os::Macos => {
                let plist = self.definition_path().unwrap().display().to_string();
                vec![
                    // bootout first so a re-install picks up a changed definition;
                    // failure (not loaded) is expected and ignored by the runner.
                    s(&["launchctl", "bootout", &format!("gui/{}/{LABEL}", uid())]),
                    s(&["launchctl", "bootstrap", &format!("gui/{}", uid()), &plist]),
                    s(&[
                        "launchctl",
                        "kickstart",
                        "-k",
                        &format!("gui/{}/{LABEL}", uid()),
                    ]),
                ]
            }
            Os::Linux => vec![
                s(&["systemctl", "--user", "daemon-reload"]),
                s(&["systemctl", "--user", "enable", "--now", UNIT]),
            ],
            Os::Windows => {
                let tr = format!(
                    "\"{}\" serve --vault \"{}\" --bind {}",
                    self.exe.display(),
                    self.vault.display(),
                    self.bind
                );
                vec![
                    s(&[
                        "schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/TN",
                        TASK, "/TR", &tr,
                    ]),
                    s(&["schtasks", "/Run", "/TN", TASK]),
                ]
            }
        }
    }

    pub fn uninstall_commands(&self) -> Vec<Vec<String>> {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        match self.os {
            Os::Macos => vec![s(&[
                "launchctl",
                "bootout",
                &format!("gui/{}/{LABEL}", uid()),
            ])],
            Os::Linux => vec![
                s(&["systemctl", "--user", "disable", "--now", UNIT]),
                s(&["systemctl", "--user", "daemon-reload"]),
            ],
            Os::Windows => vec![
                s(&["schtasks", "/End", "/TN", TASK]),
                s(&["schtasks", "/Delete", "/F", "/TN", TASK]),
            ],
        }
    }

    pub fn status_command(&self) -> Vec<String> {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        match self.os {
            Os::Macos => s(&["launchctl", "print", &format!("gui/{}/{LABEL}", uid())]),
            Os::Linux => s(&["systemctl", "--user", "status", "--no-pager", UNIT]),
            Os::Windows => s(&["schtasks", "/Query", "/TN", TASK, "/V", "/FO", "LIST"]),
        }
    }
}

fn uid() -> String {
    #[cfg(unix)]
    {
        // `id -u` avoids an unsafe libc call; launchd domains need the numeric uid.
        if let Ok(out) = Command::new("id").arg("-u").output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    "501".to_string()
}

/// `base/rest` with a forward slash regardless of host, for paths that belong
/// to a Unix target.
fn unix_join(base: &Path, rest: &str) -> PathBuf {
    let b = base.display().to_string();
    PathBuf::from(format!("{}/{}", b.trim_end_matches('/'), rest))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn systemd_quote(s: &str) -> String {
    if s.chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\'')
    {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

/// What `install`/`uninstall` did or would do.
pub struct Report {
    pub lines: Vec<String>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for l in &self.lines {
            writeln!(f, "{l}")?;
        }
        Ok(())
    }
}

fn run(cmd: &[String], tolerate_failure: bool) -> Result<String, String> {
    let out = Command::new(&cmd[0])
        .args(&cmd[1..])
        .output()
        .map_err(|e| format!("{}: {e}", cmd[0]))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() || tolerate_failure {
        Ok(text)
    } else {
        Err(format!(
            "`{}` failed ({}): {}",
            cmd.join(" "),
            out.status,
            text.trim()
        ))
    }
}

pub fn install(spec: &Spec, dry_run: bool) -> Result<Report, String> {
    let mut lines = Vec::new();
    if !spec.vault.exists() {
        return Err(format!(
            "vault {} does not exist; run `bsc init --vault {}` first",
            spec.vault.display(),
            spec.vault.display()
        ));
    }
    if let Some(def) = spec.definition() {
        let path = spec.definition_path().unwrap();
        lines.push(format!("write {}", path.display()));
        if dry_run {
            lines.push(indent(&def));
        } else {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            std::fs::create_dir_all(spec.log_dir())
                .map_err(|e| format!("{}: {e}", spec.log_dir().display()))?;
            std::fs::write(&path, def).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    for (i, cmd) in spec.install_commands().iter().enumerate() {
        lines.push(format!("run   {}", cmd.join(" ")));
        if !dry_run {
            // The first macOS command (bootout) legitimately fails when nothing is loaded.
            let tolerate = spec.os == Os::Macos && i == 0;
            let out = run(cmd, tolerate)?;
            if !out.trim().is_empty() {
                lines.push(indent(out.trim()));
            }
        }
    }
    lines.push(if dry_run {
        "dry run: nothing was written or started".to_string()
    } else {
        format!(
            "installed; the daemon starts at login and serves http://{}/",
            spec.bind
        )
    });
    Ok(Report { lines })
}

pub fn uninstall(spec: &Spec, dry_run: bool) -> Result<Report, String> {
    let mut lines = Vec::new();
    for cmd in spec.uninstall_commands() {
        lines.push(format!("run   {}", cmd.join(" ")));
        if !dry_run {
            let out = run(&cmd, true)?;
            if !out.trim().is_empty() {
                lines.push(indent(out.trim()));
            }
        }
    }
    if let Some(path) = spec.definition_path() {
        lines.push(format!("remove {}", path.display()));
        if !dry_run && path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    lines.push(if dry_run {
        "dry run: nothing was removed".to_string()
    } else {
        "uninstalled; the vault file was left in place".to_string()
    });
    Ok(Report { lines })
}

pub fn status(spec: &Spec) -> Result<String, String> {
    let cmd = spec.status_command();
    run(&cmd, true).map(|s| {
        if s.trim().is_empty() {
            "not installed".to_string()
        } else {
            s
        }
    })
}

/// Whether a definition is present (file on disk, or a scheduled task).
pub fn is_installed(spec: &Spec) -> bool {
    match spec.definition_path() {
        Some(p) => p.exists(),
        None => Command::new("schtasks")
            .args(["/Query", "/TN", TASK])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
    }
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("      {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn spec_for_current(vault: &Path, bind: &str) -> Result<Spec, String> {
    let os = Os::current().ok_or("unsupported platform for service install")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let vault = if vault.is_absolute() {
        vault.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(vault)
    };
    Ok(Spec {
        os,
        exe,
        vault,
        bind: bind.to_string(),
        home: home_dir(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(os: Os) -> Spec {
        Spec {
            os,
            exe: PathBuf::from("/opt/bin/bsc"),
            vault: PathBuf::from("/home/ann/.bsc/vault.bsc"),
            bind: "127.0.0.1:8787".into(),
            home: PathBuf::from("/home/ann"),
        }
    }

    #[test]
    fn plist_is_well_formed_and_carries_every_argument() {
        let p = spec(Os::Macos).plist();
        for must in [
            "<key>Label</key><string>io.bastet.bsc</string>",
            "<string>/opt/bin/bsc</string>",
            "<string>serve</string>",
            "<string>--vault</string>",
            "<string>/home/ann/.bsc/vault.bsc</string>",
            "<string>--bind</string>",
            "<string>127.0.0.1:8787</string>",
            "<key>RunAtLoad</key><true/>",
            "<key>KeepAlive</key><true/>",
            "<key>ThrottleInterval</key><integer>2</integer>",
            "/home/ann/Library/Logs/bsc/bsc.log",
        ] {
            assert!(p.contains(must), "missing {must}\n{p}");
        }
        assert_eq!(p.matches("<dict>").count(), p.matches("</dict>").count());
        assert_eq!(p.matches("<array>").count(), p.matches("</array>").count());
    }

    #[test]
    fn plist_escapes_xml_in_paths() {
        let mut s = spec(Os::Macos);
        s.vault = PathBuf::from("/Users/a&b/<v>.bsc");
        let p = s.plist();
        assert!(p.contains("/Users/a&amp;b/&lt;v&gt;.bsc"));
        assert!(!p.contains("a&b"));
    }

    #[test]
    fn unit_restarts_on_failure_and_is_user_scoped() {
        let u = spec(Os::Linux).unit();
        for must in [
            "ExecStart=/opt/bin/bsc serve --vault /home/ann/.bsc/vault.bsc --bind 127.0.0.1:8787",
            "Restart=on-failure",
            "WantedBy=default.target",
            "NoNewPrivileges=true",
            "UMask=0077",
            "ReadWritePaths=/home/ann/.bsc",
        ] {
            assert!(u.contains(must), "missing {must}\n{u}");
        }
    }

    #[test]
    fn unit_quotes_paths_with_spaces() {
        let mut s = spec(Os::Linux);
        s.exe = PathBuf::from("/opt/my tools/bsc");
        assert!(s.unit().contains("ExecStart=\"/opt/my tools/bsc\" serve"));
    }

    #[test]
    fn windows_uses_a_logon_task_without_elevation() {
        let s = spec(Os::Windows);
        assert!(s.definition().is_none());
        let cmds = s.install_commands();
        let create = cmds[0].join(" ");
        assert!(create.contains("/SC ONLOGON"));
        assert!(create.contains("/RL LIMITED"), "must not require admin");
        assert!(create.contains(
            "\"/opt/bin/bsc\" serve --vault \"/home/ann/.bsc/vault.bsc\" --bind 127.0.0.1:8787"
        ));
        assert_eq!(cmds[1], vec!["schtasks", "/Run", "/TN", TASK]);
        assert!(s
            .uninstall_commands()
            .iter()
            .any(|c| c.contains(&"/Delete".to_string())));
    }

    #[test]
    fn definition_paths_are_per_user() {
        assert_eq!(
            spec(Os::Macos).definition_path().unwrap(),
            PathBuf::from("/home/ann/Library/LaunchAgents/io.bastet.bsc.plist")
        );
        assert_eq!(
            spec(Os::Linux).definition_path().unwrap(),
            PathBuf::from("/home/ann/.config/systemd/user/bsc.service")
        );
    }

    #[test]
    fn macos_install_reloads_then_kickstarts() {
        let cmds = spec(Os::Macos).install_commands();
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0][1], "bootout");
        assert_eq!(cmds[1][1], "bootstrap");
        assert!(cmds[1][3].ends_with("io.bastet.bsc.plist"));
        assert_eq!(cmds[2][1], "kickstart");
    }
}
