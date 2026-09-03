//! Passphrase rotation, item deletion, pre-authorization grants, rotation
//! cadence — through the human surface the UI uses.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use bsc_crypto::kdf::KdfParams;
use bsc_daemon::{app, notify::RecordingNotifier, AppState, Config};
use bsc_store::Vault;
use reqwest::{header, Method, StatusCode};
use serde_json::{json, Value};

const PW: &str = "correct horse battery staple";
const NEW_PW: &str = "a brand new, longer passphrase";

struct H {
    _dir: tempfile::TempDir,
    base: String,
    http: reqwest::Client,
    cookie: String,
    clock: Arc<AtomicI64>,
}

async fn up() -> H {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        PW.as_bytes(),
        KdfParams::insecure_for_tests(*b"lifecycle-api-01"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let c = clock.clone();
    let state = AppState::with(
        vault,
        Config::default(),
        Arc::new(move || c.load(Ordering::SeqCst)),
        Arc::new(RecordingNotifier::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let http = reqwest::Client::new();
    let cookie = login(&http, &base, PW).await.unwrap();
    H {
        _dir: dir,
        base,
        http,
        cookie,
        clock,
    }
}

async fn login(http: &reqwest::Client, base: &str, pw: &str) -> Option<String> {
    let r = http
        .post(format!("{base}/v1/vault/unseal"))
        .header("X-BSC-Client", "t")
        .json(&json!({ "passphrase": pw }))
        .send()
        .await
        .unwrap();
    if r.status() != StatusCode::OK {
        return None;
    }
    Some(
        r.headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string(),
    )
}

impl H {
    async fn human(&self, m: Method, p: &str, b: Option<Value>) -> (StatusCode, Value) {
        let mut r = self
            .http
            .request(m, format!("{}{}", self.base, p))
            .header(header::COOKIE, &self.cookie)
            .header("X-BSC-Client", "t");
        if let Some(b) = b {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        (resp.status(), resp.json().await.unwrap_or(Value::Null))
    }
    async fn agent(&self, tok: &str, p: &str) -> (StatusCode, Value) {
        let resp = self
            .http
            .get(format!("{}{}", self.base, p))
            .bearer_auth(tok)
            .header("X-BSC-Reason", "r")
            .send()
            .await
            .unwrap();
        (resp.status(), resp.json().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn passphrase_change_requires_current_ends_sessions_and_new_one_logs_in() {
    let mut h = up().await;
    let (_, v) = h.human(Method::POST, "/v1/items", Some(json!({ "path": "p", "name": "n", "type": "api_key", "tags": [], "value": "keep-me" }))).await;
    let sref = v["sref"].as_str().unwrap().to_string();

    let (s, v) = h
        .human(
            Method::POST,
            "/v1/vault/passphrase",
            Some(json!({ "current": "wrong", "new": NEW_PW })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["error"], "bad_passphrase");
    let (s, v) = h
        .human(
            Method::POST,
            "/v1/vault/passphrase",
            Some(json!({ "current": PW, "new": "short" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    let (s, v) = h
        .human(
            Method::POST,
            "/v1/vault/passphrase",
            Some(json!({ "current": PW, "new": NEW_PW })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Old session is gone; old passphrase no longer logs in; new one does; data intact.
    let (s, _) = h.human(Method::GET, "/v1/items", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(login(&h.http, &h.base, PW).await.is_none());
    h.cookie = login(&h.http, &h.base, NEW_PW)
        .await
        .expect("new passphrase logs in");
    let (s, v) = h
        .human(
            Method::POST,
            &format!("/v1/items/{sref}/reveal"),
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["value"], "keep-me");
    let (_, audit) = h.human(Method::GET, "/v1/audit?limit=1000", None).await;
    assert!(audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["action"] == "passphrase_rotated" && r["outcome"] == "ok"));
}

#[tokio::test]
async fn delete_item_and_pre_authorized_grants() {
    let mut h = up().await;
    let (_, v) = h.human(Method::POST, "/v1/items", Some(json!({ "path": "prod/gcp", "name": "sa", "type": "service_account", "tags": [], "value": "x", "rotation_days": 30 }))).await;
    let sref = v["sref"].as_str().unwrap().to_string();
    assert_eq!(v["rotation_days"], 30);
    assert!(v["rotation_due_at"].is_string());
    let (_, v) = h
        .human(
            Method::POST,
            "/v1/tokens",
            Some(json!({ "label": "bot", "scope": { "paths": ["prod"], "tags": [] } })),
        )
        .await;
    let (tok_id, tok) = (
        v["id"].as_str().unwrap().to_string(),
        v["value"].as_str().unwrap().to_string(),
    );

    // Approval-required item pends…
    let (s, _) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    // …until a human pre-authorizes.
    let (s, v) = h
        .human(
            Method::POST,
            "/v1/grants",
            Some(json!({ "token_id": tok_id, "sref": sref, "ttl_seconds": 600 })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let (s, v) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, g) = h.human(Method::GET, "/v1/grants", None).await;
    let grants = g["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["source"], "pre-authorized");
    assert_eq!(grants[0]["token_label"], "bot");
    assert_eq!(grants[0]["item_name"], "sa");
    // Revoke → pends again.
    let (s, _) = h
        .human(Method::DELETE, &format!("/v1/grants/{tok_id}/{sref}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (s, _) = h
        .human(Method::DELETE, &format!("/v1/grants/{tok_id}/{sref}"), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Rotation cadence via PATCH, and due moves with a new version.
    h.clock.fetch_add(3600, Ordering::SeqCst);
    // An hour later the human session has idled out (15 min); log in again.
    h.cookie = login(&h.http, &h.base, PW).await.unwrap();
    let (s, v) = h
        .human(
            Method::PATCH,
            &format!("/v1/items/{sref}"),
            Some(json!({ "rotation_days": 7 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["rotation_days"], 7);

    // Delete: gone for humans and agents, ledger keeps it, pending approval denied.
    let (s, v) = h
        .human(
            Method::DELETE,
            &format!("/v1/items/{sref}"),
            Some(json!({ "reason": "decommissioned" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = h
        .human(Method::GET, &format!("/v1/items/{sref}"), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    let (_, audit) = h
        .human(
            Method::GET,
            &format!("/v1/audit?subject={sref}&limit=100"),
            None,
        )
        .await;
    let acts: Vec<&str> = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["action"].as_str().unwrap())
        .collect();
    assert!(
        acts.contains(&"item_created")
            && acts.contains(&"grant_issued")
            && acts.contains(&"grant_revoked")
            && acts.contains(&"item_deleted"),
        "{acts:?}"
    );
    let (_, inbox) = h.human(Method::GET, "/v1/approvals", None).await;
    assert!(
        inbox["approvals"].as_array().unwrap().is_empty(),
        "pending approval for a deleted item is closed"
    );
}
