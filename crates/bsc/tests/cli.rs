//! The binary itself: help text, offline ledger verification, refusal to
//! bind off-loopback, and MCP refusing a token that is not a `bsct_` value.

use std::process::Command;

use bsc_crypto::kdf::KdfParams;
use bsc_store::{Actor, Vault};

fn bsc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bsc"))
}

#[test]
fn help_lists_the_four_subcommands() {
    let out = bsc().arg("--help").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for cmd in ["init", "serve", "mcp", "audit"] {
        assert!(s.contains(cmd), "missing {cmd} in help:\n{s}");
    }
}

#[test]
fn audit_verifies_an_intact_vault_and_reports_a_broken_one() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("v.bsc");
    {
        let mut v = Vault::create_with_params(&path, b"pw", KdfParams::insecure_for_tests([7; 16]))
            .unwrap();
        v.seal(&Actor::System).unwrap();
    }
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.starts_with("intact: 2 records, head "), "{s}");

    // Break the chain from outside and the binary must say so, non-zero.
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("UPDATE audit SET outcome = 'x' WHERE n = 1", [])
        .unwrap();
    drop(c);
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("broken at record 1"));
}

#[test]
fn init_from_stdin_creates_a_vault_that_audit_verifies_and_refuses_overwrite() {
    use std::io::Write;
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("nested").join("v.bsc");
    let mut child = bsc()
        .args(["init", "--passphrase-stdin", "--vault"])
        .arg(&path)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"a passphrase for the test\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("Argon2id 64 MiB"));
    assert!(path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    // A second init must not clobber the vault.
    let mut child = bsc()
        .args(["init", "--passphrase-stdin", "--vault"])
        .arg(&path)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"x\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already exists"));
}

#[test]
fn audit_on_a_missing_vault_fails_cleanly() {
    let out = bsc()
        .args(["audit", "--vault", "/nonexistent/none.bsc"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("bsc: "));
}

#[test]
fn serve_refuses_a_non_loopback_bind() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("v.bsc");
    Vault::create_with_params(&path, b"pw", KdfParams::insecure_for_tests([8; 16])).unwrap();
    let out = bsc()
        .args(["serve", "--vault"])
        .arg(&path)
        .args(["--bind", "0.0.0.0:8787"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("only loopback"));
}

#[test]
fn mcp_refuses_a_token_that_is_not_a_bsct_value() {
    let out = bsc()
        .args(["mcp"])
        .env("BSC_TOKEN", "ghp_notours")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bsct_"));
    let out = bsc()
        .args(["mcp"])
        .env_remove("BSC_TOKEN")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("BSC_TOKEN"));
}
