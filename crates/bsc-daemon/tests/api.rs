//! End-to-end over a real socket. The error-contract test is the M2 gate.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use bsc_crypto::kdf::KdfParams;
use bsc_daemon::{app, notify::RecordingNotifier, AppState, Config};
use bsc_store::Vault;
use reqwest::{header, Method, StatusCode};
use serde_json::{json, Value};

const T0: i64 = 1_800_000_000;
const PW: &str = "correct horse battery staple";

struct H {
    _dir: tempfile::TempDir,
    base: String,
    http: reqwest::Client,
    clock: Arc<AtomicI64>,
    state: Arc<AppState>,
    notifier: Arc<RecordingNotifier>,
    cookie: String,
}

async fn harness() -> H {
    harness_with(Config::default()).await
}

async fn harness_with(cfg: Config) -> H {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        PW.as_bytes(),
        KdfParams::insecure_for_tests(*b"daemon-test-salt"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(T0));
    let c = clock.clone();
    let notifier = Arc::new(RecordingNotifier::default());
    let state = AppState::with(
        vault,
        cfg,
        Arc::new(move || c.load(Ordering::SeqCst)),
        notifier.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(listener, app(st)).await.unwrap() });
    let mut h = H {
        _dir: dir,
        base: format!("http://{addr}"),
        http: reqwest::Client::new(),
        clock,
        state,
        notifier,
        cookie: String::new(),
    };
    h.login().await;
    h
}

impl H {
    fn advance(&self, s: i64) {
        self.clock.fetch_add(s, Ordering::SeqCst);
    }

    async fn login(&mut self) {
        let r = self
            .http
            .post(format!("{}/v1/vault/unseal", self.base))
            .header("X-BSC-Client", "test")
            .json(&json!({ "passphrase": PW }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
        let sc = r
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        self.cookie = sc.split(';').next().unwrap().to_string();
    }

    async fn human(
        &self,
        m: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value, reqwest::header::HeaderMap) {
        let mut r = self
            .http
            .request(m, format!("{}{}", self.base, path))
            .header(header::COOKIE, &self.cookie)
            .header("X-BSC-Client", "test");
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        (status, v, headers)
    }

    async fn agent(
        &self,
        token: &str,
        m: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value, reqwest::header::HeaderMap) {
        let mut r = self
            .http
            .request(m, format!("{}{}", self.base, path))
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        (status, v, headers)
    }

    async fn item(&self, path: &str, name: &str, ty: &str, tags: &[&str], value: &str) -> String {
        let (s, v, _) = self
            .human(
                Method::POST,
                "/v1/items",
                Some(json!({ "path": path, "name": name, "type": ty, "tags": tags, "env": "prod", "value": value })),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        v["sref"].as_str().unwrap().to_string()
    }

    async fn mint(
        &self,
        scope: Value,
        lifetime: i64,
        max_reads: Option<u32>,
        rate: u32,
    ) -> (String, String) {
        let (s, v, _) = self
            .human(
                Method::POST,
                "/v1/tokens",
                Some(json!({ "label": "deploy-bot", "scope": scope, "lifetime": lifetime, "max_reads": max_reads, "rate_limit_per_min": rate })),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        (
            v["id"].as_str().unwrap().to_string(),
            v["value"].as_str().unwrap().to_string(),
        )
    }
}

fn scope(paths: &[&str]) -> Value {
    json!({ "paths": paths, "tags": [] })
}

fn assert_contract(v: &Value, code: &str) {
    assert_eq!(v["error"], code, "{v}");
    for k in ["message", "next_action", "do_not", "request_id"] {
        assert!(
            v[k].is_string() && !v[k].as_str().unwrap().is_empty(),
            "{code}: missing {k} in {v}"
        );
    }
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn login_sets_cookie_status_reflects_session_and_bad_passphrase_is_recorded() {
    let h = harness().await;
    let (s, v, _) = h.human(Method::GET, "/v1/vault/status", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["sealed"], false);
    assert!(v["chain"]["intact"].as_bool().unwrap());

    let anon: Value = h
        .http
        .get(format!("{}/v1/vault/status", h.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(anon["sealed"], false);
    assert!(anon.get("chain").is_none(), "no detail without a session");

    let r = h
        .http
        .post(format!("{}/v1/vault/unseal", h.base))
        .header("X-BSC-Client", "t")
        .json(&json!({ "passphrase": "wrong" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let v: Value = r.json().await.unwrap();
    assert_contract(&v, "bad_passphrase");
    let (_, audit, _) = h.human(Method::GET, "/v1/audit?limit=1000", None).await;
    let denied = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "login" && r["outcome"] == "denied")
        .count();
    assert_eq!(denied, 1);
}

#[tokio::test]
async fn human_surface_enforces_cookie_client_header_and_origin() {
    let h = harness().await;
    // No cookie.
    let r = h
        .http
        .get(format!("{}/v1/items", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_contract(&r.json().await.unwrap(), "unauthorized");
    // Cookie but no client header on a write.
    let r = h
        .http
        .post(format!("{}/v1/items", h.base))
        .header(header::COOKIE, &h.cookie)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_contract(&r.json().await.unwrap(), "forbidden_origin");
    // Foreign origin.
    let r = h
        .http
        .get(format!("{}/v1/items", h.base))
        .header(header::COOKIE, &h.cookie)
        .header(header::ORIGIN, "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Agent token never grants human surface.
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;
    let (s, v, _) = h
        .agent(
            &tok,
            Method::POST,
            "/v1/items",
            Some(json!({ "path": "p", "name": "n", "type": "api_key", "value": "x" })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_contract(&v, "forbidden_origin");
}

#[tokio::test]
async fn agent_reads_in_scope_with_reason_and_it_is_in_the_ledger() {
    let h = harness().await;
    let sref = h
        .item(
            "prod/aws",
            "billing",
            "api_key",
            &["finance"],
            "sk_live_not_real",
        )
        .await;
    let (tok_id, tok) = h.mint(scope(&["prod"]), 3600, Some(10), 60).await;

    let (s, v, hd) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=deploy%20step%203"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["value"], "sk_live_not_real");
    assert_eq!(v["version"], 1);
    assert_eq!(v["type"], "api_key");
    assert!(v["warning"].is_null());
    assert_eq!(hd.get("cache-control").unwrap(), "no-store");
    assert_eq!(hd.get("x-bsc-token-expires-in").unwrap(), "3600");
    assert_eq!(hd.get("x-bsc-reads-remaining").unwrap(), "9");

    // Reason via header works too and keeps it out of the URL.
    let r = h
        .http
        .get(format!("{}/v1/secrets/{sref}", h.base))
        .header(header::AUTHORIZATION, format!("Bearer {tok}"))
        .header("X-BSC-Reason", "second read")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let (_, audit, _) = h.human(Method::GET, "/v1/audit?limit=1000", None).await;
    let reads: Vec<&Value> = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "secret_read")
        .collect();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0]["actor"], format!("token:{tok_id}"));
    assert_eq!(reads[0]["subject"], sref);
    assert_eq!(reads[0]["meta"]["reason"], "deploy step 3");
    assert_eq!(reads[0]["outcome"], "ok");
    for r in audit["records"].as_array().unwrap() {
        assert!(
            !r.to_string().contains("sk_live_not_real"),
            "value in ledger"
        );
        assert!(!r.to_string().contains(&tok), "token value in ledger");
    }
}

#[tokio::test]
async fn list_secrets_is_scoped_filtered_and_never_carries_values() {
    let h = harness().await;
    let a = h
        .item("prod/aws", "billing", "cloud_key", &["finance"], "A")
        .await;
    let _b = h.item("staging/aws", "deploy", "api_key", &[], "B").await;
    let c = h
        .item("prod/gcp", "firebase", "service_account", &["mobile"], "C")
        .await;
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;

    let (s, v, _) = h.agent(&tok, Method::GET, "/v1/secrets", None).await;
    assert_eq!(s, StatusCode::OK);
    let items = v["items"].as_array().unwrap();
    let srefs: Vec<&str> = items.iter().map(|i| i["sref"].as_str().unwrap()).collect();
    assert_eq!(items.len(), 2);
    assert!(srefs.contains(&a.as_str()) && srefs.contains(&c.as_str()));
    assert!(!v.to_string().contains("\"value\""));
    assert_eq!(
        items.iter().find(|i| i["sref"] == c).unwrap()["approval_required"],
        true
    );

    let (_, v, _) = h
        .agent(&tok, Method::GET, "/v1/secrets?path=prod/gcp", None)
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    let (_, v, _) = h
        .agent(&tok, Method::GET, "/v1/secrets?tag=finance", None)
        .await;
    assert_eq!(v["items"][0]["sref"], a);
}

#[tokio::test]
async fn approval_flow_pending_inbox_approve_poll_once_then_grant_then_expiry() {
    let h = harness().await;
    let sref = h
        .item(
            "prod/gcp",
            "firebase-admin",
            "service_account",
            &[],
            "{\"type\":\"sa\"}",
        )
        .await;
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;

    let (s, v, hd) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=push%20notification%20deploy"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_contract(&v, "approval_pending");
    assert_eq!(v["status"], "approval_pending");
    let apr = v["approval_id"].as_str().unwrap().to_string();
    assert_eq!(hd.get("retry-after").unwrap(), "5");
    assert_eq!(
        hd.get("location").unwrap(),
        &format!("/v1/access-requests/{apr}")
    );
    assert!(v["do_not"].as_str().unwrap().contains("paste"));

    // Repeating the read does not pile up requests.
    let (_, v2, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=again"),
            None,
        )
        .await;
    assert_eq!(v2["approval_id"], apr);

    // Inbox shows the reason verbatim.
    let (_, inbox, _) = h.human(Method::GET, "/v1/approvals", None).await;
    let list = inbox["approvals"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["reason"], "push notification deploy");
    assert_eq!(list[0]["item_name"], "firebase-admin");
    assert_eq!(list[0]["token_label"], "deploy-bot");

    // Immediate notification (ladder step 1) was delivered.
    let ev = h.notifier.events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].step, 1);
    assert_eq!(ev[0].reason, "push notification deploy");

    // Poll while pending.
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/access-requests/{apr}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["status"], "pending");

    // Approve.
    let (s, v, _) = h
        .human(Method::POST, &format!("/v1/approvals/{apr}/approve"), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "approved");

    // Poll delivers the value exactly once.
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/access-requests/{apr}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "approved");
    assert_eq!(v["value"], "{\"type\":\"sa\"}");
    let (_, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/access-requests/{apr}"),
            None,
        )
        .await;
    assert_eq!(v["status"], "consumed");
    assert!(v.get("value").is_none());

    // Grant lets a direct read through without a new prompt.
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=again"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Grant expires with grant_ttl.
    h.advance(1800);
    let (s, _, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=later"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn denial_timeout_and_escalation_ladder() {
    let h = harness().await;
    let sref = h.item("prod/gcp", "sa", "service_account", &[], "v").await;
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;

    let (_, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    let apr = v["approval_id"].as_str().unwrap().to_string();
    let (_, _, _) = h
        .human(Method::POST, &format!("/v1/approvals/{apr}/deny"), None)
        .await;
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/access-requests/{apr}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_contract(&v, "approval_denied");
    // A denied pair may ask again (new request) — the human decides each time.
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r2"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let apr2 = v["approval_id"].as_str().unwrap().to_string();
    assert_ne!(apr2, apr);

    // Escalation at 20 s and 60 s, timeout at 300 s.
    h.advance(20);
    h.state.tick();
    h.advance(40);
    h.state.tick();
    let steps: Vec<u32> = h
        .notifier
        .events()
        .iter()
        .filter(|e| e.approval_id == apr2)
        .map(|e| e.step)
        .collect();
    assert_eq!(steps, vec![1, 2, 3]);
    h.advance(240);
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/access-requests/{apr2}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::REQUEST_TIMEOUT);
    assert_contract(&v, "approval_timeout");
    let (s, v, _) = h
        .human(Method::POST, &format!("/v1/approvals/{apr2}/approve"), None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn task_session_suppresses_prompt_and_lapses_without_renewal() {
    let h = harness().await;
    let sref = h.item("prod/gcp", "sa", "service_account", &[], "v").await;
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;
    let (s, v, _) = h
        .human(
            Method::POST,
            "/v1/sessions",
            Some(json!({ "scope": scope(&["prod/gcp"]), "duration_seconds": 600 })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let ses = v["id"].as_str().unwrap().to_string();

    let (s, _, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=in%20session"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    // Out-of-session-scope item still prompts.
    let other = h.item("prod/aws", "root", "cloud_key", &[], "k").await;
    let (s, _, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{other}?reason=x"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);

    h.advance(600);
    let (s, _, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=after"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "session must not renew itself");
    let (_, v, _) = h.human(Method::GET, "/v1/sessions", None).await;
    assert!(v["sessions"].as_array().unwrap().is_empty());
    let (s, _, _) = h
        .human(Method::DELETE, &format!("/v1/sessions/{ses}"), None)
        .await;
    assert_eq!(s, StatusCode::OK, "closing a lapsed session is idempotent");
}

#[tokio::test]
async fn renewal_window_expiry_warning_and_grace() {
    let h = harness().await;
    let sref = h.item("prod/x", "k", "api_key", &[], "v").await;
    let (_, tok) = h.mint(scope(&["prod"]), 1000, None, 60).await;

    // Too early to renew.
    let (s, v, _) = h.agent(&tok, Method::POST, "/v1/token/renew", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_contract(&v, "invalid_request");

    // Inside the final 20 %: warning appears.
    h.advance(850);
    let (s, v, hd) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["warning"].as_str().unwrap().contains("renew"));
    assert_eq!(hd.get("x-bsc-token-expires-in").unwrap(), "150");

    // Expired but inside grace: 401 renewable, then renew works.
    h.advance(200);
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_contract(&v, "token_expired");
    assert_eq!(v["renewable"], true);
    let (s, v, _) = h.agent(&tok, Method::POST, "/v1/token/renew", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // Let it die past grace.
    h.advance(1000 + 301);
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["renewable"], false);
    let (s, v, _) = h.agent(&tok, Method::POST, "/v1/token/renew", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_contract(&v, "token_expired");
}

#[tokio::test]
async fn sealed_vault_agent_503_human_metadata_only_and_sessions_cleared() {
    let mut h = harness().await;
    let sref = h.item("prod/x", "k", "api_key", &[], "v").await;
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;
    let (s, _, _) = h.human(Method::POST, "/v1/vault/seal", None).await;
    assert_eq!(s, StatusCode::OK);

    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_contract(&v, "vault_sealed");
    assert!(v["do_not"].as_str().unwrap().contains("passphrase"));

    // The old cookie is gone.
    let (s, _, _) = h.human(Method::GET, "/v1/items", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    h.login().await;
    let (s, v, _) = h.human(Method::GET, "/v1/items", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["sealed"], false, "login unseals");
}

#[tokio::test]
async fn reveal_requires_passphrase_only_for_approval_required_items() {
    let h = harness().await;
    let plain = h.item("prod/x", "k", "api_key", &[], "plain-value").await;
    let guarded = h
        .item("prod/gcp", "sa", "service_account", &[], "guarded-value")
        .await;

    let (s, v, _) = h
        .human(
            Method::POST,
            &format!("/v1/items/{plain}/reveal"),
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["value"], "plain-value");

    let (s, v, _) = h
        .human(
            Method::POST,
            &format!("/v1/items/{guarded}/reveal"),
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v, _) = h
        .human(
            Method::POST,
            &format!("/v1/items/{guarded}/reveal"),
            Some(json!({ "passphrase": "nope" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_contract(&v, "bad_passphrase");
    let (s, v, _) = h
        .human(
            Method::POST,
            &format!("/v1/items/{guarded}/reveal"),
            Some(json!({ "passphrase": PW })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["value"], "guarded-value");
}

#[tokio::test]
async fn versions_patch_and_binary_values() {
    let h = harness().await;
    let sref = h.item("prod/x", "k", "api_key", &[], "v1").await;
    let (s, v, _) = h
        .human(
            Method::POST,
            &format!("/v1/items/{sref}/versions"),
            Some(json!({ "value_base64": "AAEC/w==", "note": "rotated" })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["version"], 2);
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["value"].is_null());
    assert_eq!(v["value_base64"], "AAEC/w==");
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}/versions/1?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["value"], "v1");

    let (s, v, _) = h.human(Method::PATCH, &format!("/v1/items/{sref}"), Some(json!({ "approval_required": true, "local_approval_only": true, "expires_at": null }))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["approval_required"], true);
    assert_eq!(v["local_approval_only"], true);
    let (s, _, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "now approval-required");
}

/// The M2 gate: every code in API_CONTRACT §4 is reachable, carries the
/// contract shape, has the contract status, and — for every code that a
/// confused agent might resolve by asking for a paste — says not to.
#[tokio::test]
async fn error_contract_every_code_reachable_with_shape_and_status() {
    let h = harness().await;
    let sref = h.item("prod/x", "k", "api_key", &[], "v").await;
    let guarded = h.item("prod/gcp", "sa", "service_account", &[], "g").await;
    let (_, tok) = h.mint(scope(&["prod"]), 3600, None, 60).await;
    let (_, narrow) = h.mint(scope(&["staging"]), 3600, None, 60).await;
    let (_, capped) = h.mint(scope(&["prod"]), 3600, Some(1), 60).await;
    let (_, slow) = h.mint(scope(&["prod"]), 3600, None, 1).await;
    let (rev_id, revoked) = h.mint(scope(&["prod"]), 3600, None, 60).await;
    h.human(Method::DELETE, &format!("/v1/tokens/{rev_id}"), None)
        .await;
    // Lifetime 200: by the time it is checked the clock has moved 401 s, so it
    // is expired but still inside the 300 s renewal grace.
    let (_, short) = h.mint(scope(&["prod"]), 200, None, 60).await;

    let mut seen: Vec<(&str, StatusCode)> = Vec::new();
    let mut check = |code: &'static str,
                     want: StatusCode,
                     s: StatusCode,
                     v: &Value,
                     must_mention_paste: bool| {
        assert_eq!(s, want, "{code}: {v}");
        assert_contract(v, code);
        if must_mention_paste {
            assert!(
                v["do_not"]
                    .as_str()
                    .unwrap()
                    .to_lowercase()
                    .contains("paste"),
                "{code} do_not must forbid pasting: {v}"
            );
        }
        seen.push((code, s));
    };

    let (s, v, _) = h
        .agent(
            "bsct_unknown",
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    check("unauthorized", StatusCode::UNAUTHORIZED, s, &v, true);

    let (s, v, _) = h
        .agent(
            &revoked,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    check("token_revoked", StatusCode::UNAUTHORIZED, s, &v, true);

    let (s, v, _) = h
        .agent(
            &narrow,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    check("scope_mismatch", StatusCode::FORBIDDEN, s, &v, true);

    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{guarded}?reason=r"),
            None,
        )
        .await;
    check("approval_pending", StatusCode::ACCEPTED, s, &v, true);
    let apr = v["approval_id"].as_str().unwrap().to_string();
    h.human(Method::POST, &format!("/v1/approvals/{apr}/deny"), None)
        .await;
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/access-requests/{apr}"),
            None,
        )
        .await;
    check("approval_denied", StatusCode::FORBIDDEN, s, &v, true);

    let (_, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{guarded}?reason=r2"),
            None,
        )
        .await;
    let apr2 = v["approval_id"].as_str().unwrap().to_string();
    h.advance(301);
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/access-requests/{apr2}"),
            None,
        )
        .await;
    check("approval_timeout", StatusCode::REQUEST_TIMEOUT, s, &v, true);

    h.agent(
        &capped,
        Method::GET,
        &format!("/v1/secrets/{sref}?reason=r"),
        None,
    )
    .await;
    let (s, v, _) = h
        .agent(
            &capped,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    check(
        "quota_exhausted",
        StatusCode::TOO_MANY_REQUESTS,
        s,
        &v,
        true,
    );

    h.agent(
        &slow,
        Method::GET,
        &format!("/v1/secrets/{sref}?reason=r"),
        None,
    )
    .await;
    let (s, v, _) = h
        .agent(
            &slow,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    check("rate_limited", StatusCode::TOO_MANY_REQUESTS, s, &v, false);
    assert!(v["retry_after"].as_u64().unwrap() >= 1);

    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            "/v1/secrets/sref_doesnotexist?reason=r",
            None,
        )
        .await;
    check("not_found", StatusCode::NOT_FOUND, s, &v, false);

    let (s, v, _) = h
        .agent(&tok, Method::GET, &format!("/v1/secrets/{sref}"), None)
        .await;
    check("reason_required", StatusCode::BAD_REQUEST, s, &v, false);

    let (s, v, _) = h
        .agent(
            &tok,
            Method::POST,
            "/v1/access-requests",
            Some(json!({ "nope": 1 })),
        )
        .await;
    check("invalid_request", StatusCode::BAD_REQUEST, s, &v, false);

    let (s, v, _) = h
        .human(Method::POST, "/v1/handoff-links", Some(json!({})))
        .await;
    check("handoff_disabled", StatusCode::FORBIDDEN, s, &v, true);

    // token_expired both ways.
    h.advance(100);
    let (s, v, _) = h
        .agent(
            &short,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    check("token_expired", StatusCode::UNAUTHORIZED, s, &v, true);
    assert_eq!(v["renewable"], true);

    // vault_sealed last, since it changes global state.
    h.human(Method::POST, "/v1/vault/seal", None).await;
    let (s, v, _) = h
        .agent(
            &tok,
            Method::GET,
            &format!("/v1/secrets/{sref}?reason=r"),
            None,
        )
        .await;
    check("vault_sealed", StatusCode::SERVICE_UNAVAILABLE, s, &v, true);

    // Unknown route also speaks the contract.
    let r = h
        .http
        .get(format!("{}/v1/nope", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_contract(&r.json().await.unwrap(), "not_found");

    let codes: Vec<&str> = seen.iter().map(|(c, _)| *c).collect();
    for want in [
        "unauthorized",
        "token_revoked",
        "scope_mismatch",
        "approval_pending",
        "approval_denied",
        "approval_timeout",
        "quota_exhausted",
        "rate_limited",
        "not_found",
        "reason_required",
        "invalid_request",
        "handoff_disabled",
        "token_expired",
        "vault_sealed",
    ] {
        assert!(
            codes.contains(&want),
            "contract code {want} was not exercised"
        );
    }
}
