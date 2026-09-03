//! Lifecycle, items, versions, search.

use bsc_crypto::kdf::KdfParams;
use bsc_store::{
    model::{ItemType, NewItem},
    Actor, StoreError, Vault,
};
use tempfile::TempDir;

const PW: &[u8] = b"correct horse battery staple";

fn human() -> Actor {
    Actor::Human {
        session: "s1".into(),
    }
}

fn fresh() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.bsc");
    let params = KdfParams::insecure_for_tests(*b"unit-test-salt-1");
    let v = Vault::create_with_params(&path, PW, params).unwrap();
    (dir, v)
}

fn item(path: &str, name: &str, t: ItemType, tags: &[&str]) -> NewItem {
    NewItem {
        path: path.into(),
        name: name.into(),
        item_type: t,
        tags: tags.iter().map(|s| s.to_string()).collect(),
        env: Some("prod".into()),
        approval_required: None,
        expires_at: None,
        rotation_days: None,
    }
}

#[test]
fn create_opens_unsealed_and_reopen_is_sealed() {
    let (dir, v) = fresh();
    assert!(!v.is_sealed());
    let path = dir.path().join("test.bsc");
    drop(v);
    let v2 = Vault::open(&path).unwrap();
    assert!(v2.is_sealed());
    assert_eq!(v2.kdf_params().m_cost_kib, 64);
}

#[test]
fn create_refuses_existing_path_and_empty_passphrase() {
    let (dir, _v) = fresh();
    let path = dir.path().join("test.bsc");
    assert!(matches!(
        Vault::create_with_params(&path, PW, KdfParams::insecure_for_tests([0; 16])),
        Err(StoreError::Invalid(_))
    ));
    let other = dir.path().join("other.bsc");
    assert!(matches!(
        Vault::create_with_params(&other, b"", KdfParams::insecure_for_tests([0; 16])),
        Err(StoreError::Invalid(_))
    ));
}

#[cfg(unix)]
#[test]
fn vault_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _v) = fresh();
    let mode = std::fs::metadata(dir.path().join("test.bsc"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn put_read_roundtrip_and_detail() {
    let (_dir, mut v) = fresh();
    let id = v
        .put(
            item(
                "prod/aws",
                "billing-account",
                ItemType::CloudKey,
                &["finance", "AWS"],
            ),
            b"AKIA-not-real-0000",
            &human(),
            "seed",
        )
        .unwrap();
    assert!(id.starts_with("sref_"));
    assert_eq!(id.len(), 5 + 22);

    let body = v.read(&id, &human(), "test").unwrap();
    assert_eq!(&*body, b"AKIA-not-real-0000");

    let d = v.detail(&id).unwrap();
    assert_eq!(d.path, "prod/aws");
    assert_eq!(d.name, "billing-account");
    assert_eq!(d.tags, vec!["finance", "AWS"]);
    assert_eq!(d.meta.item_type, ItemType::CloudKey);
    assert!(
        d.meta.approval_required,
        "cloud keys require approval by default"
    );
    assert_eq!(d.meta.current_version, 1);
    assert_eq!(d.meta.size, 18);
}

#[test]
fn approval_default_follows_type_and_can_be_overridden() {
    let (_dir, mut v) = fresh();
    let a = v
        .put(item("p", "a", ItemType::ApiKey, &[]), b"k", &human(), "")
        .unwrap();
    let mut forced = item("p", "b", ItemType::ApiKey, &[]);
    forced.approval_required = Some(true);
    let b = v.put(forced, b"k", &human(), "").unwrap();
    let mut relaxed = item("p", "c", ItemType::ServiceAccount, &[]);
    relaxed.approval_required = Some(false);
    let c = v.put(relaxed, b"k", &human(), "").unwrap();
    assert!(!v.meta(&a).unwrap().approval_required);
    assert!(v.meta(&b).unwrap().approval_required);
    assert!(!v.meta(&c).unwrap().approval_required);
}

#[test]
fn names_and_paths_are_not_on_disk_in_the_clear() {
    let (dir, mut v) = fresh();
    v.put(
        item(
            "zebra/quokka",
            "platypus-credential",
            ItemType::ApiKey,
            &["wombat"],
        ),
        b"the-body-value",
        &human(),
        "",
    )
    .unwrap();
    drop(v);
    let mut bytes = std::fs::read(dir.path().join("test.bsc")).unwrap();
    for suffix in ["-wal", "-shm"] {
        if let Ok(more) = std::fs::read(dir.path().join(format!("test.bsc{suffix}"))) {
            bytes.extend(more);
        }
    }
    for needle in ["zebra", "quokka", "platypus", "wombat", "the-body-value"] {
        assert!(
            !contains(&bytes, needle.as_bytes()),
            "{needle} found in vault file"
        );
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn versions_append_and_old_ones_stay_readable() {
    let (_dir, mut v) = fresh();
    let id = v
        .put(item("p", "n", ItemType::ApiKey, &[]), b"v1", &human(), "")
        .unwrap();
    assert_eq!(
        v.add_version(&id, b"v2", Some("rotated"), &human(), "rotation")
            .unwrap(),
        2
    );
    assert_eq!(v.add_version(&id, b"v3", None, &human(), "").unwrap(), 3);
    assert_eq!(&*v.read(&id, &human(), "").unwrap(), b"v3");
    assert_eq!(&*v.read_version(&id, Some(1), &human(), "").unwrap(), b"v1");
    assert_eq!(&*v.read_version(&id, Some(2), &human(), "").unwrap(), b"v2");
    assert!(matches!(
        v.read_version(&id, Some(9), &human(), ""),
        Err(StoreError::NotFound)
    ));
    assert_eq!(v.meta(&id).unwrap().current_version, 3);
}

#[test]
fn sealed_vault_lists_metadata_but_refuses_reads_and_records_the_refusal() {
    let (dir, mut v) = fresh();
    let id = v
        .put(item("p", "n", ItemType::SshKey, &[]), b"key", &human(), "")
        .unwrap();
    drop(v);
    let mut v = Vault::open(&dir.path().join("test.bsc")).unwrap();

    let list = v.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id);
    assert_eq!(list[0].item_type, ItemType::SshKey);

    let before = v.audit_read(1, 1000).unwrap().len();
    assert!(matches!(
        v.read(&id, &human(), "x"),
        Err(StoreError::Sealed)
    ));
    assert!(matches!(v.detail(&id), Err(StoreError::Sealed)));
    assert!(matches!(v.search("n", &human()), Err(StoreError::Sealed)));
    let after = v.audit_read(1, 1000).unwrap();
    assert_eq!(after.len(), before + 1);
    let last = after.last().unwrap();
    assert_eq!(last.action, "secret_read");
    assert_eq!(last.outcome, "denied");
    assert_eq!(last.subject.as_deref(), Some(id.as_str()));
}

#[test]
fn unseal_with_right_and_wrong_passphrase_both_leave_records() {
    let (dir, v) = fresh();
    drop(v);
    let mut v = Vault::open(&dir.path().join("test.bsc")).unwrap();
    assert!(matches!(
        v.unseal(b"wrong", &human()),
        Err(StoreError::BadPassphrase)
    ));
    assert!(v.is_sealed());
    v.unseal(PW, &human()).unwrap();
    assert!(!v.is_sealed());
    v.seal(&human()).unwrap();
    assert!(v.is_sealed());

    let actions: Vec<(String, String)> = v
        .audit_read(1, 1000)
        .unwrap()
        .into_iter()
        .map(|r| (r.action, r.outcome))
        .collect();
    assert_eq!(
        actions,
        vec![
            ("vault_created".into(), "ok".into()),
            ("unseal".into(), "denied".into()),
            ("unseal".into(), "ok".into()),
            ("seal".into(), "ok".into()),
        ]
    );
}

#[test]
fn search_matches_tokens_across_name_path_and_tags_with_and_semantics() {
    let (_dir, mut v) = fresh();
    let aws = v
        .put(
            item(
                "prod/aws",
                "billing-account",
                ItemType::CloudKey,
                &["finance"],
            ),
            b"x",
            &human(),
            "",
        )
        .unwrap();
    let gcp = v
        .put(
            item(
                "prod/gcp",
                "Firebase-Admin",
                ItemType::ServiceAccount,
                &["mobile", "finance"],
            ),
            b"x",
            &human(),
            "",
        )
        .unwrap();
    let staging = v
        .put(
            item("staging/aws", "deploy", ItemType::CloudKey, &[]),
            b"x",
            &human(),
            "",
        )
        .unwrap();

    let mut both = vec![aws.clone(), staging.clone()];
    both.sort();
    assert_eq!(v.search("aws", &human()).unwrap(), both);
    assert_eq!(v.search("AWS prod", &human()).unwrap(), vec![aws.clone()]);
    assert_eq!(v.search("firebase", &human()).unwrap(), vec![gcp.clone()]);
    let mut fin = vec![aws.clone(), gcp.clone()];
    fin.sort();
    assert_eq!(v.search("finance", &human()).unwrap(), fin);
    assert!(v.search("nonexistent", &human()).unwrap().is_empty());
    assert!(v.search("aws mobile", &human()).unwrap().is_empty());
    assert!(v.search("   ", &human()).unwrap().is_empty());
}

#[test]
fn reads_are_recorded_before_release_with_actor_and_reason() {
    let (_dir, mut v) = fresh();
    let id = v
        .put(item("p", "n", ItemType::ApiKey, &[]), b"s", &human(), "")
        .unwrap();
    let agent = Actor::Token { id: "tok_1".into() };
    v.read(&id, &agent, "deploy step 3").unwrap();
    let last = v.audit_read(1, 1000).unwrap().pop().unwrap();
    assert_eq!(last.actor, "token:tok_1");
    assert_eq!(last.action, "secret_read");
    assert_eq!(last.outcome, "ok");
    assert_eq!(last.subject.as_deref(), Some(id.as_str()));
    let meta: serde_json::Value = serde_json::from_str(&last.meta).unwrap();
    assert_eq!(meta["reason"], "deploy step 3");
    assert_eq!(meta["version"], 1);
}

#[test]
fn missing_item_is_not_found() {
    let (_dir, mut v) = fresh();
    assert!(matches!(
        v.read("sref_nope", &human(), ""),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(v.meta("sref_nope"), Err(StoreError::NotFound)));
    assert!(matches!(
        v.add_version("sref_nope", b"x", None, &human(), ""),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn open_rejects_non_vault_file() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("junk.bsc");
    std::fs::write(&p, b"not a database").unwrap();
    assert!(Vault::open(&p).is_err());
    assert!(matches!(
        Vault::open(&dir.path().join("missing.bsc")),
        Err(StoreError::Format(_))
    ));
}
