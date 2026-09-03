//! Passphrase rotation, item deletion, pre-authorization grants, rotation cadence.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use bsc_crypto::kdf::KdfParams;
use bsc_store::{
    access::{NewToken, Scope},
    model::{ItemType, NewItem},
    Actor, StoreError, Vault,
};
use tempfile::TempDir;

const T0: i64 = 1_800_000_000;
const OLD: &[u8] = b"old passphrase";
const NEW: &[u8] = b"new passphrase, longer";

fn human() -> Actor {
    Actor::Human {
        session: "h".into(),
    }
}

fn fx() -> (TempDir, Vault, Arc<AtomicI64>) {
    let dir = TempDir::new().unwrap();
    let mut v = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        OLD,
        KdfParams::insecure_for_tests(*b"lifecycle-salt-1"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(T0));
    let c = clock.clone();
    v.set_clock(Box::new(move || c.load(Ordering::SeqCst)));
    (dir, v, clock)
}

fn item(v: &mut Vault, path: &str, name: &str, ty: ItemType, rotation_days: Option<u32>) -> String {
    v.put(
        NewItem {
            path: path.into(),
            name: name.into(),
            item_type: ty,
            tags: vec!["t1".into()],
            env: None,
            approval_required: None,
            expires_at: None,
            rotation_days,
        },
        format!("body-of-{name}").as_bytes(),
        &human(),
        "",
    )
    .unwrap()
}

#[test]
fn passphrase_rotation_keeps_everything_readable_and_kills_the_old_passphrase() {
    let (dir, mut v, _c) = fx();
    let a = item(&mut v, "prod/aws", "billing", ItemType::CloudKey, None);
    let b = item(
        &mut v,
        "prod/gcp",
        "firebase",
        ItemType::ServiceAccount,
        Some(30),
    );
    v.add_version(&a, b"body-of-billing-v2", Some("rotated"), &human(), "")
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
    let ses = v
        .open_session(
            Scope {
                paths: vec!["prod/gcp".into()],
                tags: vec![],
            },
            600,
            &human(),
        )
        .unwrap();
    v.set_item_use(
        &a,
        Some(&bsc_store::model::UseBinding {
            urls: vec!["https://api.example/*".into()],
            header: "X: {value}".into(),
            methods: vec![],
        }),
        false,
        &human(),
    )
    .unwrap();
    let params_before = v.kdf_params().clone();

    // Wrong current passphrase is refused and recorded.
    assert!(matches!(
        v.rotate_passphrase(b"nope", NEW, &human()),
        Err(StoreError::BadPassphrase)
    ));
    v.rotate_passphrase(OLD, NEW, &human()).unwrap();
    assert_ne!(v.kdf_params().salt, params_before.salt, "fresh salt");
    assert_eq!(
        v.kdf_params().m_cost_kib,
        params_before.m_cost_kib,
        "same cost class"
    );

    // Still unsealed and everything still decrypts.
    assert_eq!(&*v.read(&a, &human(), "").unwrap(), b"body-of-billing-v2");
    assert_eq!(
        &*v.read_version(&a, Some(1), &human(), "").unwrap(),
        b"body-of-billing"
    );
    assert_eq!(&*v.read(&b, &human(), "").unwrap(), b"body-of-firebase");
    let d = v.detail(&a).unwrap();
    assert_eq!(d.name, "billing");
    assert_eq!(d.tags, vec!["t1"]);
    assert_eq!(d.use_binding.unwrap().header, "X: {value}");
    assert_eq!(
        v.token(&tok.record.id).unwrap().label.as_deref(),
        Some("bot")
    );
    assert_eq!(
        v.session(&ses.id).unwrap().scope.unwrap().paths,
        vec!["prod/gcp"]
    );
    // Blind index was rebuilt under the new index key.
    assert_eq!(v.search("firebase", &human()).unwrap(), vec![b.clone()]);
    assert_eq!(v.search("prod", &human()).unwrap().len(), 2);

    // Reopen: old passphrase dead, new one works, token value still valid.
    drop(v);
    let mut v = Vault::open(&dir.path().join("v.bsc")).unwrap();
    assert!(matches!(
        v.unseal(OLD, &human()),
        Err(StoreError::BadPassphrase)
    ));
    v.unseal(NEW, &human()).unwrap();
    assert_eq!(&*v.read(&b, &human(), "").unwrap(), b"body-of-firebase");
    assert!(v.token_by_value(&tok.value).unwrap().is_some());
    let actions: Vec<(String, String)> = v
        .audit_read(1, 1000)
        .unwrap()
        .into_iter()
        .filter(|r| r.action == "passphrase_rotated")
        .map(|r| (r.action, r.outcome))
        .collect();
    assert_eq!(
        actions,
        vec![
            ("passphrase_rotated".into(), "denied".into()),
            ("passphrase_rotated".into(), "ok".into())
        ]
    );
}

#[test]
fn delete_removes_item_versions_index_grants_and_denies_pending_approvals() {
    let (_d, mut v, _c) = fx();
    let a = item(
        &mut v,
        "prod/gcp",
        "firebase",
        ItemType::ServiceAccount,
        None,
    );
    let keep = item(&mut v, "prod/aws", "billing", ItemType::CloudKey, None);
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
    let apr = v
        .request_approval(&tok.record.id, &a, "r", 300, &human())
        .unwrap();
    v.grant_direct(&tok.record.id, &keep, 600, &human())
        .unwrap();
    v.grant_direct(&tok.record.id, &a, 600, &human()).unwrap();

    v.delete_item(&a, &human(), "no longer used").unwrap();
    assert!(matches!(v.meta(&a), Err(StoreError::NotFound)));
    assert!(matches!(
        v.read(&a, &human(), ""),
        Err(StoreError::NotFound)
    ));
    assert_eq!(v.list().unwrap().len(), 1);
    assert!(
        v.search("firebase", &human()).unwrap().is_empty(),
        "index rows gone"
    );
    assert!(!v.has_grant(&tok.record.id, &a).unwrap());
    assert!(
        v.has_grant(&tok.record.id, &keep).unwrap(),
        "other grants untouched"
    );
    assert_eq!(
        v.approval(&apr.id).unwrap().status.as_str(),
        "denied",
        "pending approval closed"
    );
    let last = v
        .audit_read(1, 1000)
        .unwrap()
        .into_iter()
        .rev()
        .find(|r| r.action == "item_deleted")
        .unwrap();
    assert_eq!(last.subject.as_deref(), Some(a.as_str()));
    assert!(matches!(
        v.delete_item(&a, &human(), ""),
        Err(StoreError::NotFound)
    ));
    // Sealed vault cannot delete.
    v.seal(&human()).unwrap();
    assert!(matches!(
        v.delete_item(&keep, &human(), ""),
        Err(StoreError::Sealed)
    ));
}

#[test]
fn pre_authorization_grants_are_capped_listed_and_revocable() {
    let (_d, mut v, clock) = fx();
    let a = item(
        &mut v,
        "prod/gcp",
        "firebase",
        ItemType::ServiceAccount,
        None,
    );
    let tok = v
        .mint_token(
            NewToken {
                label: "bot".into(),
                scope: Scope {
                    paths: vec!["prod".into()],
                    tags: vec![],
                },
                lifetime: 1000,
                max_lifetime: 86_400,
                max_reads: None,
                rate_limit_per_min: 60,
            },
            &human(),
        )
        .unwrap();
    assert!(matches!(
        v.grant_direct(&tok.record.id, &a, 0, &human()),
        Err(StoreError::Invalid(_))
    ));
    let until = v.grant_direct(&tok.record.id, &a, 7200, &human()).unwrap();
    assert_eq!(until, T0 + 1000, "capped at token expiry");
    assert!(v.has_grant(&tok.record.id, &a).unwrap());
    let grants = v.active_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].approval_id, "pre");
    assert!(v.revoke_grant(&tok.record.id, &a, &human()).unwrap());
    assert!(
        !v.revoke_grant(&tok.record.id, &a, &human()).unwrap(),
        "second revoke is a no-op"
    );
    assert!(!v.has_grant(&tok.record.id, &a).unwrap());
    v.grant_direct(&tok.record.id, &a, 100, &human()).unwrap();
    clock.fetch_add(100, Ordering::SeqCst);
    assert!(!v.has_grant(&tok.record.id, &a).unwrap());
    assert!(v.active_grants().unwrap().is_empty());
    let actions: Vec<String> = v
        .audit_read(1, 1000)
        .unwrap()
        .into_iter()
        .map(|r| r.action)
        .filter(|a| a.starts_with("grant_"))
        .collect();
    assert_eq!(
        actions,
        vec!["grant_issued", "grant_revoked", "grant_issued"]
    );
}

#[test]
fn rotation_cadence_is_stored_and_due_is_derived_from_updated() {
    let (_d, mut v, clock) = fx();
    let a = item(&mut v, "prod/aws", "billing", ItemType::CloudKey, Some(30));
    let m = v.meta(&a).unwrap();
    assert_eq!(m.rotation_days, Some(30));
    assert_eq!(m.rotation_due_at(), Some(T0 + 30 * 86_400));
    // A new version resets the clock; changing the cadence does not.
    clock.fetch_add(10 * 86_400, Ordering::SeqCst);
    v.add_version(&a, b"v2", None, &human(), "rotation")
        .unwrap();
    assert_eq!(
        v.meta(&a).unwrap().rotation_due_at(),
        Some(T0 + 40 * 86_400)
    );
    let m = v
        .set_item_flags(&a, None, None, None, None, Some(Some(7)), &human())
        .unwrap();
    assert_eq!(m.rotation_due_at(), Some(T0 + 17 * 86_400));
    let m = v
        .set_item_flags(&a, None, None, None, None, Some(None), &human())
        .unwrap();
    assert_eq!(m.rotation_due_at(), None);
}
