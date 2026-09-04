//! The restore drill (M7 gate).
//!
//! A backup nobody has ever restored is a rumour. This exercises both recovery
//! routes end to end, through the real binary where the binary is what an
//! operator would run:
//!
//!   1. **File backup** — copy the vault file, lose the original, put the copy
//!      back. Same passphrase, same ledger, same contents.
//!   2. **Break-glass export** — `bsc export` under a second passphrase, then
//!      `bsc import` into a *new* vault with a *new* passphrase, the way a
//!      successor with no access to the original machine would have to.
//!
//! It also asserts the failures that make a backup worth having: the copy is
//! useless without the passphrase, and the export is useless with the wrong one.

use std::io::Write;

use bsc_crypto::kdf::KdfParams;
use bsc_store::{
    model::{ItemType, NewItem},
    Actor, Vault,
};

fn bsc() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_bsc"))
}

fn run(args: &[&str], stdin: &str) -> std::process::Output {
    let mut c = bsc()
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

const PW: &[u8] = b"the original passphrase";
const ITEMS: [(&str, &str, ItemType, &[u8]); 3] = [
    ("prod/aws", "root-key", ItemType::CloudKey, b"AKIA-secret"),
    (
        "prod/gcp",
        "deployer",
        ItemType::ServiceAccount,
        b"{\"type\":\"service_account\"}",
    ),
    ("dev", "laptop", ItemType::SshKey, b"-----BEGIN KEY-----"),
];

/// A vault with three items, the middle one carrying two versions.
fn populated(path: &std::path::Path) -> Vec<String> {
    let mut v = Vault::create_with_params(
        path,
        PW,
        KdfParams::insecure_for_tests(*b"drill-salt-00001"),
    )
    .unwrap();
    let mut srefs = Vec::new();
    for (p, n, ty, body) in ITEMS {
        let id = v
            .put(
                NewItem {
                    path: p.into(),
                    name: n.into(),
                    item_type: ty,
                    tags: vec!["drill".into()],
                    env: None,
                    approval_required: None,
                    expires_at: None,
                    rotation_days: None,
                },
                body,
                &Actor::System,
                "",
            )
            .unwrap();
        srefs.push(id);
    }
    v.add_version(
        &srefs[1],
        b"{\"rotated\":true}",
        Some("rotation"),
        &Actor::System,
        "drill",
    )
    .unwrap();
    srefs
}

fn assert_contents(v: &mut Vault, srefs: &[String]) {
    for (i, (p, n, _, body)) in ITEMS.iter().enumerate() {
        let d = v.detail(&srefs[i]).unwrap();
        assert_eq!(&d.path, p);
        assert_eq!(&d.name, n);
        let want: &[u8] = if i == 1 { b"{\"rotated\":true}" } else { body };
        assert_eq!(
            v.read(&srefs[i], &Actor::System, "drill")
                .unwrap()
                .as_slice(),
            want,
            "item {n} came back wrong"
        );
    }
    // The rotated item kept its history.
    assert_eq!(
        v.read_version(&srefs[1], Some(1), &Actor::System, "drill")
            .unwrap()
            .as_slice(),
        ITEMS[1].3
    );
}

#[test]
fn a_copied_vault_file_restores_completely() {
    let dir = tempfile::TempDir::new().unwrap();
    let live = dir.path().join("vault.bsc");
    let backup = dir.path().join("backup/vault.bsc");
    let srefs = populated(&live);

    // Back up: the file is already encrypted, so copying it is the whole job.
    // (The connection is closed above, so WAL contents are checkpointed in.)
    std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
    std::fs::copy(&live, &backup).unwrap();

    // The chain verifies on the backup while it is still sealed — which is how
    // an operator checks a backup without unsealing anything.
    let out = run(&["audit", "--vault", backup.to_str().unwrap()], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("intact"));

    // Lose the original the way a disk does: it is simply not there any more.
    std::fs::remove_file(&live).unwrap();
    for side in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(live.with_extension(format!("bsc{side}")));
    }
    assert!(Vault::open(&live).is_err());

    // Restore.
    std::fs::copy(&backup, &live).unwrap();
    let mut v = Vault::open(&live).unwrap();
    v.unseal(PW, &Actor::System).unwrap();
    assert_contents(&mut v, &srefs);
    v.audit_verify().unwrap();
}

#[test]
fn a_backup_without_the_passphrase_is_just_bytes() {
    let dir = tempfile::TempDir::new().unwrap();
    let live = dir.path().join("vault.bsc");
    populated(&live);
    let backup = dir.path().join("backup.bsc");
    std::fs::copy(&live, &backup).unwrap();

    let mut v = Vault::open(&backup).unwrap();
    assert!(v.unseal(b"a plausible guess", &Actor::System).is_err());
    // Sealed means sealed: the list is metadata only, and no name comes back.
    let listed = v.list().unwrap();
    assert_eq!(listed.len(), 3);
    let raw = std::fs::read(&backup).unwrap();
    for (_, name, _, body) in ITEMS {
        assert!(
            !raw.windows(name.len()).any(|w| w == name.as_bytes()),
            "the item name {name} is readable in the backup file"
        );
        assert!(!raw.windows(body.len()).any(|w| w == body));
    }
}

#[test]
fn break_glass_export_restores_into_a_new_vault_with_a_new_passphrase() {
    let dir = tempfile::TempDir::new().unwrap();
    let live = dir.path().join("vault.bsc");
    let srefs = populated(&live);
    let bundle = dir.path().join("break-glass.bscx");

    let out = run(
        &[
            "export",
            "--vault",
            live.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
            "--passphrase-stdin",
        ],
        "the original passphrase\nthe export passphrase\n",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(bundle.exists());

    // The successor has the bundle and the export passphrase — nothing else.
    // They start a vault of their own, with a passphrase of their own.
    std::fs::remove_file(&live).unwrap();
    let fresh = dir.path().join("successor.bsc");
    {
        let _ = Vault::create_with_params(
            &fresh,
            b"the successor's passphrase",
            KdfParams::insecure_for_tests(*b"drill-salt-00002"),
        )
        .unwrap();
    }
    let out = run(
        &[
            "import",
            "--vault",
            fresh.to_str().unwrap(),
            "--in",
            bundle.to_str().unwrap(),
            "--passphrase-stdin",
        ],
        "the successor's passphrase\nthe export passphrase\n",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut v = Vault::open(&fresh).unwrap();
    v.unseal(b"the successor's passphrase", &Actor::System)
        .unwrap();
    assert_eq!(v.list().unwrap().len(), 3);
    // References are new — an import is a new vault, not a clone — so match on
    // what the operator actually knows: the path.
    let new_srefs: Vec<String> = ITEMS
        .iter()
        .map(|(p, _, _, _)| {
            v.list()
                .unwrap()
                .into_iter()
                .map(|m| v.detail(&m.id).unwrap())
                .find(|d| &d.path == p)
                .unwrap_or_else(|| panic!("{p} did not survive the round trip"))
                .meta
                .id
        })
        .collect();
    assert!(new_srefs.iter().all(|s| !srefs.contains(s)));
    assert_contents(&mut v, &new_srefs);
    v.audit_verify().unwrap();
}

#[test]
fn the_export_refuses_the_wrong_passphrase_on_the_way_back_in() {
    let dir = tempfile::TempDir::new().unwrap();
    let live = dir.path().join("vault.bsc");
    populated(&live);
    let bundle = dir.path().join("b.bscx");
    let out = run(
        &[
            "export",
            "--vault",
            live.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
            "--passphrase-stdin",
        ],
        "the original passphrase\nthe export passphrase\n",
    );
    assert!(out.status.success());

    let target = dir.path().join("t.bsc");
    {
        let _ = Vault::create_with_params(
            &target,
            b"target passphrase",
            KdfParams::insecure_for_tests(*b"drill-salt-00003"),
        )
        .unwrap();
    }
    // The vault passphrase is not the export passphrase, and guessing does not
    // help: the bundle is authenticated.
    for wrong in ["target passphrase", "the originl passphrase", ""] {
        let out = run(
            &[
                "import",
                "--vault",
                target.to_str().unwrap(),
                "--in",
                bundle.to_str().unwrap(),
                "--passphrase-stdin",
            ],
            &format!("target passphrase\n{wrong}\n"),
        );
        assert!(!out.status.success(), "import accepted {wrong:?}");
    }
    let mut v = Vault::open(&target).unwrap();
    v.unseal(b"target passphrase", &Actor::System).unwrap();
    assert!(
        v.list().unwrap().is_empty(),
        "a failed import left rows behind"
    );
}
