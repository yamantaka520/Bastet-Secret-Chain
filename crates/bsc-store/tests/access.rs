//! Tokens, sessions, approvals, grants — with a movable clock.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use bsc_crypto::kdf::KdfParams;
use bsc_store::{
    access::{ApprovalStatus, NewToken, Scope, SessionRecord, TokenRecord},
    model::{ItemType, NewItem},
    Actor, StoreError, Vault,
};
use tempfile::TempDir;

const T0: i64 = 1_800_000_000;

fn human() -> Actor {
    Actor::Human {
        session: "ses_h".into(),
    }
}

struct Fx {
    _dir: TempDir,
    v: Vault,
    clock: Arc<AtomicI64>,
}

impl Fx {
    fn new() -> Fx {
        let dir = TempDir::new().unwrap();
        let mut v = Vault::create_with_params(
            &dir.path().join("v.bsc"),
            b"pw",
            KdfParams::insecure_for_tests(*b"access-test-salt"),
        )
        .unwrap();
        let clock = Arc::new(AtomicI64::new(T0));
        let c = clock.clone();
        v.set_clock(Box::new(move || c.load(Ordering::SeqCst)));
        Fx {
            _dir: dir,
            v,
            clock,
        }
    }
    fn advance(&self, secs: i64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }
    fn item(&mut self, path: &str, tags: &[&str], t: ItemType) -> String {
        self.v
            .put(
                NewItem {
                    path: path.into(),
                    name: "n".into(),
                    item_type: t,
                    tags: tags.iter().map(|s| s.to_string()).collect(),
                    env: None,
                    approval_required: None,
                    expires_at: None,
                    rotation_days: None,
                },
                b"body",
                &human(),
                "",
            )
            .unwrap()
    }
    fn token(
        &mut self,
        scope: Scope,
        lifetime: i64,
        max_reads: Option<u32>,
    ) -> (TokenRecord, String) {
        let m = self
            .v
            .mint_token(
                NewToken {
                    label: "deploy-bot".into(),
                    scope,
                    lifetime,
                    max_lifetime: 30 * 86_400,
                    max_reads,
                    rate_limit_per_min: 60,
                },
                &human(),
            )
            .unwrap();
        (m.record, m.value.to_string())
    }
}

fn paths(p: &[&str]) -> Scope {
    Scope {
        paths: p.iter().map(|s| s.to_string()).collect(),
        tags: vec![],
    }
}

#[test]
fn scope_matches_on_segment_boundaries_and_tags() {
    let s = Scope {
        paths: vec!["prod/aws".into()],
        tags: vec!["finance".into()],
    };
    assert!(s.covers("prod/aws", &[]));
    assert!(s.covers("prod/aws/billing", &[]));
    assert!(!s.covers("prod/awsx", &[]), "prefix must end at a segment");
    assert!(!s.covers("prod", &[]));
    assert!(!s.covers("staging/aws", &[]));
    assert!(s.covers("anything", &["finance".into()]));
    assert!(!Scope::default().covers("prod/aws", &["finance".into()]));
    assert!(paths(&["prod/aws/x"]).within(&paths(&["prod"])));
    assert!(!paths(&["prod"]).within(&paths(&["prod/aws"])));
}

#[test]
fn mint_returns_value_once_and_stores_only_a_hash() {
    let mut fx = Fx::new();
    let (rec, value) = fx.token(paths(&["prod"]), 3600, Some(5));
    assert!(value.starts_with("bsct_"));
    assert_eq!(value.len(), 5 + 43);
    assert!(rec.id.starts_with("tok_"));
    assert_eq!(rec.label.as_deref(), Some("deploy-bot"));
    assert_eq!(rec.expires_at, T0 + 3600);
    assert_eq!(rec.max_lifetime_until, T0 + 30 * 86_400);
    assert_eq!(rec.reads_remaining(), Some(5));

    let found = fx.v.token_by_value(&value).unwrap().unwrap();
    assert_eq!(found.id, rec.id);
    assert!(fx.v.token_by_value("bsct_nope").unwrap().is_none());

    // Neither the value nor the label is in the file.
    let bytes = std::fs::read(fx._dir.path().join("v.bsc")).unwrap();
    assert!(!bytes.windows(value.len()).any(|w| w == value.as_bytes()));
    assert!(!bytes.windows(10).any(|w| w == b"deploy-bot"));
}

#[test]
fn sealed_vault_can_authenticate_a_token_but_not_see_its_scope() {
    let mut fx = Fx::new();
    let (rec, value) = fx.token(paths(&["prod"]), 3600, None);
    fx.v.seal(&human()).unwrap();
    let t = fx.v.token_by_value(&value).unwrap().unwrap();
    assert_eq!(t.id, rec.id);
    assert!(t.label.is_none());
    assert!(t.scope.is_none());
    assert!(t.is_live(T0 + 1));
}

#[test]
fn mint_validates_input() {
    let mut fx = Fx::new();
    let bad = |label: &str, scope: Scope, lifetime: i64, max: i64| NewToken {
        label: label.into(),
        scope,
        lifetime,
        max_lifetime: max,
        max_reads: None,
        rate_limit_per_min: 60,
    };
    assert!(matches!(
        fx.v.mint_token(bad("x", Scope::default(), 60, 60), &human()),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        fx.v.mint_token(bad("", paths(&["p"]), 60, 60), &human()),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        fx.v.mint_token(bad("x", paths(&["p"]), 0, 60), &human()),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        fx.v.mint_token(bad("x", paths(&["p"]), 120, 60), &human()),
        Err(StoreError::Invalid(_))
    ));
}

#[test]
fn expiry_renewal_window_and_cap() {
    let mut fx = Fx::new();
    let (rec, _) = fx.token(paths(&["prod"]), 1000, None);
    assert!(rec.is_live(T0 + 999));
    assert!(!rec.is_live(T0 + 1000));

    // Too early: before the final 25 %.
    assert!(!rec.is_renewable(T0 + 749));
    assert!(matches!(
        fx.v.renew_token(&rec.id, &human()),
        Err(StoreError::Invalid(_))
    ));
    fx.advance(750);
    let r = fx.v.renew_token(&rec.id, &human()).unwrap();
    assert_eq!(r.expires_at, T0 + 2000, "extended by one lifetime");

    // Expired but inside the 5-minute grace: still renewable.
    fx.advance(2000 - 750 + TokenRecord::RENEWAL_GRACE - 1);
    let t = fx.v.token(&rec.id).unwrap();
    assert!(!t.is_live(fx.v.now()));
    assert!(t.is_renewable(fx.v.now()));
    let r = fx.v.renew_token(&rec.id, &human()).unwrap();
    assert_eq!(r.expires_at, T0 + 3000);

    // Past grace: gone for good.
    fx.advance(1000 + TokenRecord::RENEWAL_GRACE + 1);
    assert!(matches!(
        fx.v.renew_token(&rec.id, &human()),
        Err(StoreError::Invalid(_))
    ));

    // Denied renewals are in the ledger too.
    let denied =
        fx.v.audit_read(1, 1000)
            .unwrap()
            .into_iter()
            .filter(|r| r.action == "token_renewed" && r.outcome == "denied")
            .count();
    assert_eq!(denied, 2);
}

#[test]
fn renewal_never_passes_max_lifetime() {
    let mut fx = Fx::new();
    let m =
        fx.v.mint_token(
            NewToken {
                label: "short".into(),
                scope: paths(&["p"]),
                lifetime: 100,
                max_lifetime: 150,
                max_reads: None,
                rate_limit_per_min: 60,
            },
            &human(),
        )
        .unwrap();
    fx.advance(80);
    let r = fx.v.renew_token(&m.record.id, &human()).unwrap();
    assert_eq!(r.expires_at, T0 + 150, "capped");
    fx.advance(60);
    assert!(
        !r.is_renewable(fx.v.now()),
        "at the cap there is nothing left to renew"
    );
}

#[test]
fn revoked_tokens_are_dead_and_revoke_is_idempotent() {
    let mut fx = Fx::new();
    let (rec, _) = fx.token(paths(&["p"]), 3600, None);
    let r = fx.v.revoke_token(&rec.id, &human()).unwrap();
    assert!(r.revoked_at.is_some());
    assert!(!r.is_live(T0 + 1));
    assert!(!r.is_renewable(T0 + 3500));
    let before = fx.v.audit_read(1, 1000).unwrap().len();
    fx.v.revoke_token(&rec.id, &human()).unwrap();
    assert_eq!(
        fx.v.audit_read(1, 1000).unwrap().len(),
        before,
        "second revoke leaves no record"
    );
}

#[test]
fn read_quota_counts_down_and_refuses_at_zero() {
    let mut fx = Fx::new();
    let (rec, _) = fx.token(paths(&["p"]), 3600, Some(2));
    assert_eq!(fx.v.consume_read(&rec.id).unwrap(), Some(1));
    assert_eq!(fx.v.consume_read(&rec.id).unwrap(), Some(0));
    assert!(matches!(
        fx.v.consume_read(&rec.id),
        Err(StoreError::Invalid(_))
    ));
    let (uncapped, _) = fx.token(paths(&["p"]), 3600, None);
    assert_eq!(fx.v.consume_read(&uncapped.id).unwrap(), None);
}

#[test]
fn sessions_open_expire_close_and_hide_scope_when_sealed() {
    let mut fx = Fx::new();
    let s = fx.v.open_session(paths(&["prod"]), 1800, &human()).unwrap();
    assert!(s.id.starts_with("ses_"));
    assert!(s.is_active(T0));
    assert_eq!(fx.v.active_sessions().unwrap().len(), 1);
    fx.advance(1800);
    assert!(fx.v.active_sessions().unwrap().is_empty(), "no auto-renew");

    let s2 = fx.v.open_session(paths(&["prod"]), 600, &human()).unwrap();
    fx.v.close_session(&s2.id, &human()).unwrap();
    assert!(fx.v.active_sessions().unwrap().is_empty());
    assert!(matches!(
        fx.v.open_session(paths(&["p"]), SessionRecord::MAX_DURATION + 1, &human()),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        fx.v.open_session(Scope::default(), 60, &human()),
        Err(StoreError::Invalid(_))
    ));

    let s3 = fx.v.open_session(paths(&["prod"]), 600, &human()).unwrap();
    fx.v.seal(&human()).unwrap();
    let hidden = fx.v.session(&s3.id).unwrap();
    assert!(hidden.scope.is_none());
}

#[test]
fn approval_lifecycle_approve_grants_and_consumes_once() {
    let mut fx = Fx::new();
    let item = fx.item("prod/gcp", &[], ItemType::ServiceAccount);
    let (tok, _) = fx.token(paths(&["prod"]), 3600, None);

    let a =
        fx.v.request_approval(&tok.id, &item, "deploy step 3", 300, &human())
            .unwrap();
    assert!(a.id.starts_with("apr_"));
    assert_eq!(a.status, ApprovalStatus::Pending);
    assert_eq!(a.expires_at, T0 + 300);
    assert_eq!(a.reason, "deploy step 3");

    // A second request for the same pair while pending returns the same one.
    let again =
        fx.v.request_approval(&tok.id, &item, "other words", 300, &human())
            .unwrap();
    assert_eq!(again.id, a.id);
    assert_eq!(fx.v.pending_approvals().unwrap().len(), 1);

    assert!(!fx.v.has_grant(&tok.id, &item).unwrap());
    let d = fx.v.decide_approval(&a.id, true, 1800, &human()).unwrap();
    assert_eq!(d.status, ApprovalStatus::Approved);
    assert_eq!(d.decided_by.as_deref(), Some("human:ses_h"));
    assert!(fx.v.has_grant(&tok.id, &item).unwrap());
    assert!(fx.v.pending_approvals().unwrap().is_empty());

    assert!(fx.v.consume_approval(&a.id).unwrap());
    assert!(
        !fx.v.consume_approval(&a.id).unwrap(),
        "value handed over once"
    );

    // Deciding twice is refused.
    assert!(matches!(
        fx.v.decide_approval(&a.id, false, 0, &human()),
        Err(StoreError::Invalid(_))
    ));

    // Grant is capped at token expiry, and expires.
    fx.advance(1800);
    assert!(!fx.v.has_grant(&tok.id, &item).unwrap());
}

#[test]
fn grant_is_capped_at_token_expiry() {
    let mut fx = Fx::new();
    let item = fx.item("prod/gcp", &[], ItemType::ServiceAccount);
    let (tok, _) = fx.token(paths(&["prod"]), 100, None);
    let a =
        fx.v.request_approval(&tok.id, &item, "r", 300, &human())
            .unwrap();
    fx.v.decide_approval(&a.id, true, 1800, &human()).unwrap();
    fx.advance(99);
    assert!(fx.v.has_grant(&tok.id, &item).unwrap());
    fx.advance(1);
    assert!(!fx.v.has_grant(&tok.id, &item).unwrap());
}

#[test]
fn denial_leaves_no_grant_and_consume_fails() {
    let mut fx = Fx::new();
    let item = fx.item("prod/gcp", &[], ItemType::ServiceAccount);
    let (tok, _) = fx.token(paths(&["prod"]), 3600, None);
    let a =
        fx.v.request_approval(&tok.id, &item, "r", 300, &human())
            .unwrap();
    let d = fx.v.decide_approval(&a.id, false, 1800, &human()).unwrap();
    assert_eq!(d.status, ApprovalStatus::Denied);
    assert!(!fx.v.has_grant(&tok.id, &item).unwrap());
    assert!(!fx.v.consume_approval(&a.id).unwrap());
}

#[test]
fn timeout_and_escalation_follow_the_ladder_and_are_recorded() {
    let mut fx = Fx::new();
    let item = fx.item("prod/gcp", &[], ItemType::ServiceAccount);
    let (tok, _) = fx.token(paths(&["prod"]), 3600, None);
    let a =
        fx.v.request_approval(&tok.id, &item, "r", 300, &human())
            .unwrap();
    let ladder = [0, 20, 60];

    // t=0: step 1 (the immediate notification) is due.
    assert_eq!(
        fx.v.escalate_approvals(&ladder).unwrap(),
        vec![(a.id.clone(), 1)]
    );
    assert!(
        fx.v.escalate_approvals(&ladder).unwrap().is_empty(),
        "each step once"
    );
    fx.advance(20);
    assert_eq!(
        fx.v.escalate_approvals(&ladder).unwrap(),
        vec![(a.id.clone(), 2)]
    );
    fx.advance(45); // t=65: step 3
    assert_eq!(
        fx.v.escalate_approvals(&ladder).unwrap(),
        vec![(a.id.clone(), 3)]
    );
    assert!(fx.v.timeout_approvals().unwrap().is_empty());

    fx.advance(300);
    assert_eq!(fx.v.timeout_approvals().unwrap(), vec![a.id.clone()]);
    assert_eq!(
        fx.v.approval(&a.id).unwrap().status,
        ApprovalStatus::Timeout
    );
    assert!(
        fx.v.escalate_approvals(&ladder).unwrap().is_empty(),
        "no escalation after timeout"
    );
    assert!(matches!(
        fx.v.decide_approval(&a.id, true, 60, &human()),
        Err(StoreError::Invalid(_))
    ));

    let actions: Vec<String> =
        fx.v.audit_read(1, 1000)
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .filter(|a| a.starts_with("approval_"))
            .collect();
    assert_eq!(
        actions,
        vec![
            "approval_requested",
            "approval_escalated",
            "approval_escalated",
            "approval_escalated",
            "approval_timeout"
        ]
    );
}

#[test]
fn item_flags_update_and_default_local_only_is_false() {
    let mut fx = Fx::new();
    let item = fx.item("prod/gcp", &[], ItemType::ApiKey);
    let m = fx.v.meta(&item).unwrap();
    assert!(!m.approval_required);
    assert!(!m.local_approval_only);
    let m =
        fx.v.set_item_flags(
            &item,
            Some(true),
            Some(true),
            Some(Some(T0 + 86_400)),
            Some(Some("prod".into())),
            None,
            &human(),
        )
        .unwrap();
    assert!(m.approval_required);
    assert!(m.local_approval_only);
    assert_eq!(m.expires_at, Some(T0 + 86_400));
    assert_eq!(m.env.as_deref(), Some("prod"));
    let m =
        fx.v.set_item_flags(&item, None, None, Some(None), None, None, &human())
            .unwrap();
    assert_eq!(m.expires_at, None);
    assert!(m.approval_required, "untouched fields stay");
}

#[test]
fn scope_prefix_tolerates_glob_and_trailing_slash_spellings() {
    use bsc_store::access::Scope;
    let sc = |p: &str| Scope {
        paths: vec![p.into()],
        tags: vec![],
    };
    for spelling in ["test", "test/", "test/*", " test/* "] {
        let s = sc(spelling);
        assert!(s.covers("test/telegram-probe", &[]), "{spelling:?}");
        assert!(s.covers("test", &[]), "{spelling:?}");
        assert!(!s.covers("testing/x", &[]), "{spelling:?}");
        assert!(!s.covers("prod/test", &[]), "{spelling:?}");
    }
    // Inner scopes written with a glob still sit inside the outer prefix.
    assert!(sc("test/a/*").within(&sc("test")));
    assert!(!sc("prod/*").within(&sc("test/*")));
    // A lone `*` means everything; a literal `*` never sneaks into a path match.
    assert!(sc("*").covers("anything/at/all", &[]));
    assert!(!sc("te*").covers("test/x", &[]));
}
