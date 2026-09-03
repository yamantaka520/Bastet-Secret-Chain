//! A vault file written by a schema-1 binary (M1–M5) must open, migrate in
//! one transaction, and work with the schema-2 code. This is the exact shape
//! of the 2026-09-04 production vault.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use bsc_crypto::kdf::KdfParams;
use bsc_store::{
    access::{NewToken, Scope},
    model::{ItemType, NewItem},
    Actor, Vault,
};
use rusqlite::Connection;
use tempfile::TempDir;

const T0: i64 = 1_800_000_000;
const PW: &[u8] = b"migrate passphrase";

fn human() -> Actor {
    Actor::Human {
        session: "h".into(),
    }
}

/// Create a current vault with one item, one token and one pending approval,
/// then rewrite the file into the schema-1 shape.
fn schema1_vault(dir: &TempDir) -> (std::path::PathBuf, String, String) {
    let path = dir.path().join("v.bsc");
    let mut v = Vault::create_with_params(
        &path,
        PW,
        KdfParams::insecure_for_tests(*b"migrate-salt-001"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(T0));
    let c = clock.clone();
    v.set_clock(Box::new(move || c.load(Ordering::SeqCst)));
    let item = v
        .put(
            NewItem {
                path: "prod/aws".into(),
                name: "root".into(),
                item_type: ItemType::CloudKey,
                tags: vec!["t1".into()],
                env: Some("prod".into()),
                approval_required: Some(true),
                expires_at: None,
                rotation_days: None,
            },
            b"AKIA-body",
            &human(),
            "",
        )
        .unwrap();
    let tok = v
        .mint_token(
            NewToken {
                label: "bot".into(),
                scope: Scope {
                    paths: vec!["prod".into()],
                    tags: vec![],
                },
                lifetime: 3600,
                max_lifetime: 86_400,
                max_reads: None,
                rate_limit_per_min: 60,
            },
            &human(),
        )
        .unwrap();
    v.request_approval(&tok.record.id, &item, "r", 300, &human())
        .unwrap();
    v.grant_direct(&tok.record.id, &item, 600, &human())
        .unwrap();
    drop(v);

    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"
PRAGMA foreign_keys = OFF;
ALTER TABLE item DROP COLUMN use_ct;
ALTER TABLE item DROP COLUMN rotation_days;
CREATE TABLE approval_v1 (
    id TEXT PRIMARY KEY, token_id TEXT NOT NULL REFERENCES token(id),
    item_id TEXT NOT NULL REFERENCES item(id), reason TEXT NOT NULL,
    requested_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL,
    decided_at INTEGER, decided_by TEXT, consumed_at INTEGER,
    escalation INTEGER NOT NULL DEFAULT 0
);
INSERT INTO approval_v1 SELECT * FROM approval;
DROP TABLE approval;
ALTER TABLE approval_v1 RENAME TO approval;
CREATE INDEX approval_pending ON approval(status, expires_at);
CREATE TABLE access_grant_v1 (
    token_id TEXT NOT NULL REFERENCES token(id),
    item_id TEXT NOT NULL REFERENCES item(id),
    approval_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY (token_id, item_id)
);
INSERT INTO access_grant_v1 SELECT * FROM access_grant;
DROP TABLE access_grant;
ALTER TABLE access_grant_v1 RENAME TO access_grant;
UPDATE meta SET value = '1' WHERE key = 'schema_version';
"#,
    )
    .unwrap();
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('item')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(!cols.contains(&"use_ct".to_string()));
    (path, item, tok.record.id.clone())
}

fn meta(path: &std::path::Path, key: &str) -> String {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .unwrap()
}

#[test]
fn schema1_file_opens_migrates_once_and_works() {
    let dir = TempDir::new().unwrap();
    let (path, item, tok) = schema1_vault(&dir);
    assert_eq!(meta(&path, "schema_version"), "1");

    // Open migrates, sealed, before any passphrase is needed.
    let mut v = Vault::open(&path).unwrap();
    assert_eq!(meta(&path, "schema_version"), "2");
    v.unseal(PW, &human()).unwrap();

    // The query that failed in production.
    let list = v.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, item);
    assert!(!list[0].has_use_binding);
    assert_eq!(list[0].rotation_days, None);

    // Data survived: body, token, approval, grant.
    assert_eq!(
        v.read(&item, &human(), "").unwrap().as_slice(),
        b"AKIA-body"
    );
    assert!(v.active_grants().unwrap().iter().any(|g| g.token_id == tok));
    assert_eq!(v.pending_approvals().unwrap().len(), 1);

    // Schema-2 features work on the migrated file.
    v.set_item_flags(&item, None, None, None, None, Some(Some(30)), &human())
        .unwrap();
    assert_eq!(v.meta(&item).unwrap().rotation_days, Some(30));
    // Deleting an item with approval history needs the FK gone.
    v.delete_item(&item, &human(), "cleanup").unwrap();
    assert!(v.list().unwrap().is_empty());
    assert!(v.active_grants().unwrap().is_empty());

    // The ledger is intact and records the migration exactly once.
    v.audit_verify().unwrap();
    let recs = v.audit_read(0, 1000).unwrap();
    let migrations: Vec<_> = recs
        .iter()
        .filter(|r| r.action == "schema_migrated")
        .collect();
    assert_eq!(migrations.len(), 1);
    assert_eq!(migrations[0].actor, "system");
    drop(v);

    // Reopening does not migrate again.
    let v = Vault::open(&path).unwrap();
    let recs = v.audit_read(0, 1000).unwrap();
    assert_eq!(
        recs.iter()
            .filter(|r| r.action == "schema_migrated")
            .count(),
        1
    );
}

#[test]
fn newer_schema_is_refused() {
    let dir = TempDir::new().unwrap();
    let (path, _, _) = schema1_vault(&dir);
    Connection::open(&path)
        .unwrap()
        .execute_batch("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        .unwrap();
    let err = match Vault::open(&path) {
        Ok(_) => panic!("opened a newer schema"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("newer"), "{err}");
    assert_eq!(meta(&path, "schema_version"), "99");
}
