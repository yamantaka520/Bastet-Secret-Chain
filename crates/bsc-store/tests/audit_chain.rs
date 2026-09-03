//! The ledger detects edits, deletions, and reordering.

use bsc_crypto::kdf::KdfParams;
use bsc_store::{
    audit::{compute_hash, ChainStatus, HASH_LEN},
    model::{ItemType, NewItem},
    Actor, Vault,
};
use rusqlite::{params, Connection};
use tempfile::TempDir;

fn human() -> Actor {
    Actor::Human {
        session: "s".into(),
    }
}

fn populated() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("v.bsc");
    let mut v = Vault::create_with_params(
        &path,
        b"pw",
        KdfParams::insecure_for_tests(*b"audit-test-salt1"),
    )
    .unwrap();
    for i in 0..3 {
        let id = v
            .put(
                NewItem {
                    path: "p".into(),
                    name: format!("n{i}"),
                    item_type: ItemType::ApiKey,
                    tags: vec![],
                    env: None,
                    approval_required: None,
                    expires_at: None,
                },
                b"body",
                &human(),
                "",
            )
            .unwrap();
        v.read(&id, &human(), "r").unwrap();
    }
    v.seal(&human()).unwrap();
    drop(v);
    (dir, path)
}

fn raw(path: &std::path::Path) -> Connection {
    Connection::open(path).unwrap()
}

#[test]
fn fresh_chain_is_intact_and_links_genesis() {
    let (_d, path) = populated();
    let v = Vault::open(&path).unwrap();
    let status = v.audit_verify().unwrap();
    let ChainStatus::Intact { len, head } = status else {
        panic!("expected intact, got {status:?}");
    };
    assert_eq!(len, 8, "created + 3×(item_created, secret_read) + seal");
    let recs = v.audit_read(1, 100).unwrap();
    assert_eq!(recs[0].prev_hash, [0u8; HASH_LEN]);
    assert_eq!(recs.last().unwrap().hash, head);
    for w in recs.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].hash);
        assert_eq!(w[1].n, w[0].n + 1);
    }
}

#[test]
fn editing_a_field_breaks_the_chain_at_that_record() {
    let (_d, path) = populated();
    raw(&path)
        .execute("UPDATE audit SET outcome = 'denied' WHERE n = 4", [])
        .unwrap();
    assert_eq!(
        Vault::open(&path).unwrap().audit_verify().unwrap(),
        ChainStatus::Broken { at: 4 }
    );
}

#[test]
fn recomputing_one_hash_without_successors_still_breaks() {
    // An attacker who edits record 4 *and* fixes its hash still breaks
    // record 5, whose prev_hash no longer matches.
    let (_d, path) = populated();
    let c = raw(&path);
    let (ts, actor, action, subject, meta, prev): (
        i64,
        String,
        String,
        Option<String>,
        String,
        Vec<u8>,
    ) = c
        .query_row(
            "SELECT ts, actor, action, subject, meta, prev_hash FROM audit WHERE n = 4",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .unwrap();
    let mut p = [0u8; HASH_LEN];
    p.copy_from_slice(&prev);
    let new_hash = compute_hash(
        4,
        ts,
        &actor,
        &action,
        subject.as_deref(),
        "denied",
        &meta,
        &p,
    );
    c.execute(
        "UPDATE audit SET outcome = 'denied', hash = ?1 WHERE n = 4",
        params![new_hash.as_slice()],
    )
    .unwrap();
    assert_eq!(
        Vault::open(&path).unwrap().audit_verify().unwrap(),
        ChainStatus::Broken { at: 5 }
    );
}

#[test]
fn deleting_a_middle_record_breaks_the_chain() {
    let (_d, path) = populated();
    raw(&path)
        .execute("DELETE FROM audit WHERE n = 3", [])
        .unwrap();
    assert_eq!(
        Vault::open(&path).unwrap().audit_verify().unwrap(),
        ChainStatus::Broken { at: 4 }
    );
}

#[test]
fn truncating_the_tail_is_undetectable_without_an_anchor() {
    // Documented residual risk (ADR 0004): the chain verifies after tail
    // deletion. The head hash must be anchored elsewhere to catch this.
    let (_d, path) = populated();
    let before = Vault::open(&path).unwrap().audit_verify().unwrap();
    raw(&path)
        .execute("DELETE FROM audit WHERE n > 6", [])
        .unwrap();
    let after = Vault::open(&path).unwrap().audit_verify().unwrap();
    let (ChainStatus::Intact { len: l1, head: h1 }, ChainStatus::Intact { len: l2, head: h2 }) =
        (before, after)
    else {
        panic!("both should verify");
    };
    assert_eq!(l1, 8);
    assert_eq!(l2, 6);
    assert_ne!(h1, h2, "the anchored head is what reveals the truncation");
}

#[test]
fn hash_encoding_is_not_ambiguous_across_field_boundaries() {
    let p = [0u8; HASH_LEN];
    let a = compute_hash(1, 0, "ab", "c", None, "ok", "{}", &p);
    let b = compute_hash(1, 0, "a", "bc", None, "ok", "{}", &p);
    assert_ne!(a, b);
    let c = compute_hash(1, 0, "a", "b", Some(""), "ok", "{}", &p);
    let d = compute_hash(1, 0, "a", "b", None, "ok", "{}", &p);
    assert_ne!(c, d, "empty subject and no subject are different records");
}

#[test]
fn chain_hash_is_pinned() {
    // Known-answer vector for the ledger hash. Changing this value is a
    // format change and must come with a migration.
    let p = [0u8; HASH_LEN];
    let h = compute_hash(
        1,
        1_700_000_000,
        "system",
        "vault_created",
        None,
        "ok",
        "{}",
        &p,
    );
    assert_eq!(
        hex::encode(h),
        "90e5472bd1cb9176cd85833f1280142b0d1adc70db7feacc83b9dfd5182a26c6"
    );
}
