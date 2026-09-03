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

#[test]
fn anchors_detect_tail_truncation_and_rewrites() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("v.bsc");
    let anchors = dir.path().join("elsewhere").join("anchors.jsonl");
    {
        let mut v = Vault::create_with_params(&path, b"pw", KdfParams::insecure_for_tests([3; 16]))
            .unwrap();
        v.seal(&Actor::System).unwrap();
        v.unseal(b"pw", &Actor::System).unwrap();
        v.seal(&Actor::System).unwrap(); // 4 records
    }
    // First run: nothing to check, one anchor written.
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&path)
        .arg("--anchor-file")
        .arg(&anchors)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("anchors: 0 checked") && s.contains("anchored: len 4"),
        "{s}"
    );
    assert_eq!(
        std::fs::read_to_string(&anchors).unwrap().lines().count(),
        1
    );

    // Second run: consistent, a second anchor appended.
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&path)
        .arg("--anchor-file")
        .arg(&anchors)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("anchors: 1 checked, consistent"));
    assert_eq!(
        std::fs::read_to_string(&anchors).unwrap().lines().count(),
        2
    );

    // Cut the tail: the chain itself still verifies (ADR 0004 residual) but the anchor catches it.
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("DELETE FROM audit WHERE n > 2", []).unwrap();
    drop(c);
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&path)
        .arg("--anchor-file")
        .arg(&anchors)
        .arg("--no-anchor")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(
        e.contains("TAIL TRUNCATED") && e.contains("recorded 4 records") && e.contains("now has 2"),
        "{e}"
    );
    // Without an anchor file the same vault passes — which is exactly the gap anchors close.
    let out = bsc()
        .args(["audit", "--vault"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn export_and_import_through_the_binary() {
    use std::io::Write;
    let dir = tempfile::TempDir::new().unwrap();
    let src = dir.path().join("src.bsc");
    {
        let mut v =
            Vault::create_with_params(&src, b"vault pw", KdfParams::insecure_for_tests([5; 16]))
                .unwrap();
        v.put(
            bsc_store::model::NewItem {
                path: "p".into(),
                name: "n".into(),
                item_type: bsc_store::model::ItemType::ApiKey,
                tags: vec![],
                env: None,
                approval_required: None,
                expires_at: None,
                rotation_days: None,
            },
            b"the-value",
            &Actor::System,
            "",
        )
        .unwrap();
    }
    let out_file = dir.path().join("backup.bscx");
    let run = |args: &[&str], stdin: &str| {
        let mut c = bsc()
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
    };
    // Same passphrase for vault and export is refused.
    let o = run(
        &[
            "export",
            "--passphrase-stdin",
            "--vault",
            src.to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ],
        "vault pw\nvault pw\n",
    );
    assert!(!o.status.success() && String::from_utf8_lossy(&o.stderr).contains("must differ"));
    let o = run(
        &[
            "export",
            "--passphrase-stdin",
            "--vault",
            src.to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ],
        "vault pw\nexport pw\n",
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("exported 1 items"));
    assert!(!std::fs::read(&out_file)
        .unwrap()
        .windows(9)
        .any(|w| w == b"the-value"));
    // Refuses to overwrite.
    let o = run(
        &[
            "export",
            "--passphrase-stdin",
            "--vault",
            src.to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ],
        "vault pw\nexport pw\n",
    );
    assert!(
        !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("refusing to overwrite")
    );

    let dst = dir.path().join("dst.bsc");
    Vault::create_with_params(&dst, b"dst pw", KdfParams::insecure_for_tests([6; 16])).unwrap();
    let o = run(
        &[
            "import",
            "--passphrase-stdin",
            "--vault",
            dst.to_str().unwrap(),
            "--in",
            out_file.to_str().unwrap(),
        ],
        "dst pw\nwrong export pw\n",
    );
    assert!(
        !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("cannot open bundle")
    );
    let o = run(
        &[
            "import",
            "--passphrase-stdin",
            "--vault",
            dst.to_str().unwrap(),
            "--in",
            out_file.to_str().unwrap(),
        ],
        "dst pw\nexport pw\n",
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let printed = String::from_utf8_lossy(&o.stdout);
    assert!(
        printed.trim().starts_with("sref_"),
        "prints the new sref: {printed}"
    );
    let mut w = Vault::open(&dst).unwrap();
    w.unseal(b"dst pw", &Actor::System).unwrap();
    assert_eq!(
        &*w.read(printed.trim(), &Actor::System, "").unwrap(),
        b"the-value"
    );
}
