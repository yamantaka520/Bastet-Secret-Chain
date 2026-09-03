//! Opt-in unattended unseal through a systemd-style credential directory.
//! The binary is started for real on a random port; the ledger must show
//! `unseal_unattended` with its source, and a wrong credential must refuse to
//! start rather than sit sealed and silent.

use std::{
    io::Write,
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn bsc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bsc"))
}

fn init_vault(dir: &std::path::Path, pw: &str) -> std::path::PathBuf {
    let path = dir.join("v.bsc");
    let mut child = bsc()
        .args(["init", "--passphrase-stdin", "--vault"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{pw}\n").as_bytes())
        .unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_status(port: u16, child: &mut Child) -> Option<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return None; // exited
        }
        if let Ok(r) = reqwest::blocking::get(format!("http://127.0.0.1:{port}/v1/vault/status")) {
            if let Ok(v) = r.json::<serde_json::Value>() {
                return Some(v);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn credential_unseals_at_start_and_the_ledger_says_so() {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = init_vault(dir.path(), "a long unattended passphrase");
    let creds = dir.path().join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(
        creds.join("bsc-passphrase"),
        b"a long unattended passphrase\n",
    )
    .unwrap();
    let port = free_port();
    let child = bsc()
        .args(["serve", "--vault"])
        .arg(&vault)
        .args([
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--unseal-credential",
            "bsc-passphrase",
        ])
        .env("CREDENTIALS_DIRECTORY", &creds)
        .env("HOME", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut g = Guard(child);
    let status = wait_status(port, &mut g.0).expect("daemon should come up");
    assert_eq!(status["sealed"], false, "{status}");
    assert_eq!(
        status["unattended_unseal"], "systemd-credential",
        "{status}"
    );

    // Log in as a human to read the ledger.
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("http://127.0.0.1:{port}/v1/vault/unseal"))
        .header("X-BSC-Client", "test")
        .json(&serde_json::json!({ "passphrase": "a long unattended passphrase" }))
        .send()
        .unwrap();
    let cookie = r
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let audit: serde_json::Value = c
        .get(format!("http://127.0.0.1:{port}/v1/audit?limit=100"))
        .header("Cookie", &cookie)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let rec = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "unseal_unattended")
        .expect("unseal_unattended in ledger");
    assert_eq!(rec["actor"], "system");
    assert_eq!(rec["outcome"], "ok");
    assert_eq!(rec["meta"]["source"], "systemd-credential");
}

#[test]
fn wrong_credential_refuses_to_start_and_is_recorded_as_denied() {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = init_vault(dir.path(), "right passphrase");
    let creds = dir.path().join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("bsc-passphrase"), b"wrong passphrase").unwrap();
    let port = free_port();
    let out = bsc()
        .args(["serve", "--vault"])
        .arg(&vault)
        .args([
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--unseal-credential",
            "bsc-passphrase",
        ])
        .env("CREDENTIALS_DIRECTORY", &creds)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success(), "must not start sealed-and-silent");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unattended unseal from systemd-credential failed"),
        "{err}"
    );

    // The refusal is in the ledger: open the vault sealed and check via the audit CLI count.
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&vault)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.starts_with("intact: 2 records"),
        "vault_created + denied unseal_unattended: {s}"
    );
}

#[test]
fn credential_flag_without_the_directory_is_a_clear_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = init_vault(dir.path(), "pw");
    let out = bsc()
        .args(["serve", "--vault"])
        .arg(&vault)
        .args(["--bind", "127.0.0.1:1", "--unseal-credential", "x"])
        .env_remove("CREDENTIALS_DIRECTORY")
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("CREDENTIALS_DIRECTORY is not set"));
}
