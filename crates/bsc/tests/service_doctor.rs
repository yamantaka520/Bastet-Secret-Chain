//! `bsc service --dry-run` and `bsc doctor` through the real binary.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use bsc_crypto::kdf::KdfParams;
use bsc_daemon::{app, notify::RecordingNotifier, AppState, Config};
use bsc_store::Vault;

fn bsc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bsc"))
}

fn mkvault(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("v.bsc");
    Vault::create_with_params(&path, b"pw", KdfParams::insecure_for_tests([9; 16])).unwrap();
    path
}

#[test]
fn service_install_dry_run_prints_definition_and_commands_without_touching_the_system() {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = mkvault(dir.path());
    let fake_home = dir.path().join("home");
    std::fs::create_dir_all(&fake_home).unwrap();
    let out = bsc()
        .args([
            "service",
            "install",
            "--dry-run",
            "--bind",
            "127.0.0.1:8899",
            "--vault",
        ])
        .arg(&vault)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("dry run: nothing was written or started"), "{s}");
    assert!(s.contains("127.0.0.1:8899"), "{s}");
    assert!(s.contains(&vault.display().to_string()), "{s}");
    if cfg!(target_os = "macos") {
        assert!(s.contains("Library/LaunchAgents/io.bastet.bsc.plist"));
        assert!(s.contains("<key>KeepAlive</key><true/>"));
        assert!(s.contains("launchctl bootstrap"));
    } else if cfg!(target_os = "linux") {
        assert!(s.contains(".config/systemd/user/bsc.service"));
        assert!(s.contains("Restart=on-failure"));
        assert!(s.contains("systemctl --user enable --now bsc"));
    } else if cfg!(target_os = "windows") {
        assert!(s.contains("schtasks /Create"));
        assert!(s.contains("/SC ONLOGON"));
    }
    // Nothing was written under the fake home.
    let entries: Vec<_> = walk(&fake_home);
    assert!(entries.is_empty(), "dry run wrote {entries:?}");

    let out = bsc()
        .args(["service", "uninstall", "--dry-run", "--vault"])
        .arg(&vault)
        .env("HOME", &fake_home)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("dry run: nothing was removed"));
}

fn walk(p: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                v.extend(walk(&path));
            } else {
                v.push(path);
            }
        }
    }
    v
}

#[test]
fn service_install_refuses_without_a_vault() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = bsc()
        .args(["service", "install", "--dry-run", "--vault"])
        .arg(dir.path().join("none.bsc"))
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bsc init"));
}

#[test]
fn doctor_fails_on_a_missing_vault_and_warns_on_a_stopped_daemon() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = bsc()
        .args(["doctor", "--url", "http://127.0.0.1:1", "--vault"])
        .arg(dir.path().join("none.bsc"))
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success(), "missing vault is a failure");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("❌ vault"), "{s}");
    assert!(
        s.contains("⚠️  daemon") && s.contains("not reachable"),
        "{s}"
    );

    let vault = mkvault(dir.path());
    let out = bsc()
        .args(["doctor", "--url", "http://127.0.0.1:1", "--vault"])
        .arg(&vault)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "a stopped daemon is only a warning:\n{s}"
    );
    assert!(s.contains("✅ vault"), "{s}");
    assert!(s.contains("✅ format") && s.contains("Argon2id"), "{s}");
    assert!(s.contains("✅ audit chain") && s.contains("intact"), "{s}");
    assert!(s.contains("✅ writable"), "{s}");
    assert!(s.contains("✅ bind"), "{s}");
    assert!(
        s.contains("⚠️  auto-start") && s.contains("not installed"),
        "{s}"
    );
    assert!(s.contains("✅ clock"), "{s}");
}

#[test]
fn doctor_detects_a_broken_ledger_and_a_non_loopback_url() {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = mkvault(dir.path());
    let c = rusqlite::Connection::open(&vault).unwrap();
    c.execute("UPDATE audit SET outcome = 'x' WHERE n = 1", [])
        .unwrap();
    drop(c);
    let out = bsc()
        .args(["doctor", "--url", "http://10.0.0.5:8787", "--vault"])
        .arg(&vault)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("❌ audit chain") && s.contains("BROKEN at record 1"),
        "{s}"
    );
    assert!(
        s.contains("❌ bind") && s.contains("neither loopback nor https"),
        "{s}"
    );
}

#[tokio::test]
async fn doctor_bind_verdict_follows_the_daemons_declared_public_origin() {
    let dir = tempfile::TempDir::new().unwrap();
    let vault_path = mkvault(dir.path());
    let vault = Vault::open(&vault_path).unwrap();
    let cfg = Config {
        public_origin: Some("https://sec.example".into()),
        ..Config::default()
    };
    let state = AppState::with(
        vault,
        cfg,
        std::sync::Arc::new(|| 1_800_000_000),
        std::sync::Arc::new(RecordingNotifier::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let url = format!("http://{addr}");
    let home = dir.path().to_path_buf();
    let vp = vault_path.clone();
    let out = tokio::task::spawn_blocking(move || {
        bsc()
            .args(["doctor", "--url", &url, "--vault"])
            .arg(&vp)
            .env("HOME", &home)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{s}");
    assert!(
        s.contains("✅ bind") && s.contains("also declares public origin https://sec.example"),
        "{s}"
    );

    // An unreachable public https URL is a warning, not a failure.
    let out = bsc()
        .args(["doctor", "--url", "https://127.0.0.2:1", "--vault"])
        .arg(&vault_path)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{s}");
    assert!(
        s.contains("⚠️  bind") && s.contains("public https URL"),
        "{s}"
    );
}

#[tokio::test]
async fn doctor_sees_a_running_daemon_and_its_ui() {
    let dir = tempfile::TempDir::new().unwrap();
    let vault_path = mkvault(dir.path());
    let vault = Vault::open(&vault_path).unwrap();
    let state = AppState::with(
        vault,
        Config::default(),
        std::sync::Arc::new(|| 1_800_000_000),
        std::sync::Arc::new(RecordingNotifier::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });

    // doctor opens the vault file too; SQLite WAL allows the second reader.
    let url = format!("http://{addr}");
    let home = dir.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        bsc()
            .args(["doctor", "--url", &url, "--vault"])
            .arg(&vault_path)
            .env("HOME", &home)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{s}");
    assert!(
        s.contains("✅ daemon") && s.contains("running v") && s.contains("sealed"),
        "{s}"
    );
    assert!(s.contains("web ui"), "{s}");
}

#[test]
fn doctor_is_not_confused_by_an_unrelated_stdin() {
    // Regression guard: subcommands other than init must never block on stdin.
    let dir = tempfile::TempDir::new().unwrap();
    let vault = mkvault(dir.path());
    let mut child = bsc()
        .args(["doctor", "--url", "http://127.0.0.1:1", "--vault"])
        .arg(&vault)
        .env("HOME", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"garbage\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
}
