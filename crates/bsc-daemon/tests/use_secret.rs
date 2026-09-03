//! `use_secret`: the credential goes to the upstream, never to the agent.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc, Mutex,
};

use axum::{extract::State as AxState, http::HeaderMap, routing::any, Router};
use bsc_crypto::kdf::KdfParams;
use bsc_daemon::{app, notify::RecordingNotifier, AppState, Config};
use bsc_store::Vault;
use reqwest::{header, Method, StatusCode};
use serde_json::{json, Value};

const PW: &str = "correct horse battery staple";
const SECRET: &str = "sk_live_upstream_only_7f3a";

/// A stand-in provider that records what it received.
#[derive(Default)]
struct Seen {
    auth: Mutex<Vec<String>>,
    paths: Mutex<Vec<String>>,
}

async fn upstream(seen: Arc<Seen>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/*path",
            any(
                |AxState(s): AxState<Arc<Seen>>,
                 headers: HeaderMap,
                 uri: axum::http::Uri,
                 body: String| async move {
                    s.auth.lock().unwrap().push(
                        headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string(),
                    );
                    s.paths.lock().unwrap().push(uri.path().to_string());
                    (
                        StatusCode::CREATED,
                        [
                            ("x-request-id", "up-42"),
                            ("content-type", "application/json"),
                        ],
                        format!(
                            "{{\"ok\":true,\"echo\":{}}}",
                            if body.is_empty() {
                                "null".to_string()
                            } else {
                                body
                            }
                        ),
                    )
                },
            ),
        )
        .with_state(seen);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // Plain http on loopback; the daemon under test runs with
    // allow_private_upstreams, which relaxes both the SSRF guard and the
    // https-only rule so this mock can be reached.
    format!("http://{addr}")
}

struct H {
    _dir: tempfile::TempDir,
    base: String,
    http: reqwest::Client,
    cookie: String,
    seen: Arc<Seen>,
    up: String,
}

async fn harness() -> H {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        PW.as_bytes(),
        KdfParams::insecure_for_tests(*b"use-secret-salt!"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let cfg = Config {
        allow_private_upstreams: true,
        ..Config::default()
    };
    let state = AppState::with(
        vault,
        cfg,
        Arc::new(move || clock.load(Ordering::SeqCst)),
        Arc::new(RecordingNotifier::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{base}/v1/vault/unseal"))
        .header("X-BSC-Client", "t")
        .json(&json!({ "passphrase": PW }))
        .send()
        .await
        .unwrap();
    let cookie = r
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let seen = Arc::new(Seen::default());
    let up = upstream(seen.clone()).await;
    H {
        _dir: dir,
        base,
        http,
        cookie,
        seen,
        up,
    }
}

impl H {
    async fn human(&self, m: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut r = self
            .http
            .request(m, format!("{}{}", self.base, path))
            .header(header::COOKIE, &self.cookie)
            .header("X-BSC-Client", "t");
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let s = resp.status();
        (s, resp.json().await.unwrap_or(Value::Null))
    }
    async fn agent(
        &self,
        tok: &str,
        m: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut r = self
            .http
            .request(m, format!("{}{}", self.base, path))
            .header(header::AUTHORIZATION, format!("Bearer {tok}"));
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let s = resp.status();
        (s, resp.json().await.unwrap_or(Value::Null))
    }
    async fn item(&self, ty: &str, value: &str) -> String {
        let (s, v) = self.human(Method::POST, "/v1/items", Some(json!({ "path": "prod/pay", "name": "stripe", "type": ty, "tags": [], "env": "prod", "value": value }))).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        v["sref"].as_str().unwrap().to_string()
    }
    async fn token(&self, paths: &[&str]) -> String {
        let (s, v) = self.human(Method::POST, "/v1/tokens", Some(json!({ "label": "bot", "scope": { "paths": paths, "tags": [] }, "lifetime": 3600 }))).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        v["value"].as_str().unwrap().to_string()
    }
    async fn bind(
        &self,
        sref: &str,
        urls: &[&str],
        header: &str,
        methods: &[&str],
    ) -> (StatusCode, Value) {
        self.human(
            Method::PUT,
            &format!("/v1/items/{sref}/use"),
            Some(json!({ "binding": { "urls": urls, "header": header, "methods": methods } })),
        )
        .await
    }
}

#[tokio::test]
async fn binding_validation() {
    let h = harness().await;
    let sref = h.item("api_key", SECRET).await;
    let (s, v) = h
        .bind(&sref, &["https://api.example/*"], "X-Api-Key: {value}", &[])
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["use_binding"]["urls"][0], "https://api.example/*");
    // header must carry {value}
    let (s, _) = h
        .bind(&sref, &["https://api.example/*"], "X-Api-Key: fixed", &[])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // a pattern without a host is refused (this harness runs relaxed, so
    // plain http is allowed here; the strict-mode refusal is tested below)
    let (s, _) = h
        .bind(&sref, &["https://*"], "X-Api-Key: {value}", &[])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = h.bind(&sref, &[], "X-Api-Key: {value}", &[]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "empty url list");
    // listing shows the flag, detail shows the binding, and a token never sees the header template value
    let (_, list) = h.human(Method::GET, "/v1/items", None).await;
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["sref"] == sref)
        .unwrap();
    assert_eq!(row["has_use_binding"], true);
    // clear it
    let (s, v) = h
        .human(
            Method::PUT,
            &format!("/v1/items/{sref}/use"),
            Some(json!({ "binding": null })),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["use_binding"].is_null());
}

#[tokio::test]
async fn use_without_binding_or_outside_binding_is_refused_with_contract_errors() {
    let h = harness().await;
    let sref = h.item("api_key", SECRET).await;
    let tok = h.token(&["prod"]).await;
    let body = |url: &str, method: &str| json!({ "reason": "charge order 9", "url": url, "method": method });

    let (s, v) = h
        .agent(
            &tok,
            Method::POST,
            &format!("/v1/secrets/{sref}/use"),
            Some(body("https://api.example/v1/charges", "GET")),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "use_not_configured");
    assert!(v["do_not"].as_str().unwrap().contains("paste"));

    h.bind(
        &sref,
        &["https://api.example/v1/*"],
        "Authorization: Bearer {value}",
        &["GET", "POST"],
    )
    .await;
    let (s, v) = h
        .agent(
            &tok,
            Method::POST,
            &format!("/v1/secrets/{sref}/use"),
            Some(body("https://api.example/v2/other", "GET")),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"], "use_not_allowed");
    let (s, v) = h
        .agent(
            &tok,
            Method::POST,
            &format!("/v1/secrets/{sref}/use"),
            Some(body("https://api.example/v1/charges", "DELETE")),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["message"].as_str().unwrap().contains("DELETE"));
    let (s, v) = h
        .agent(
            &tok,
            Method::POST,
            &format!("/v1/secrets/{sref}/use"),
            Some(body("http://api.example/v1/charges", "GET")),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "plain http is never allowed: {v}");
    // reason still required
    let (s, v) = h
        .agent(
            &tok,
            Method::POST,
            &format!("/v1/secrets/{sref}/use"),
            Some(json!({ "url": "https://api.example/v1/x" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], "reason_required");
    // Nothing reached any upstream and nothing was read.
    assert!(h.seen.auth.lock().unwrap().is_empty());
    let (_, audit) = h.human(Method::GET, "/v1/audit?limit=1000", None).await;
    assert!(!audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["action"] == "secret_used" || r["action"] == "secret_read"));
}

#[tokio::test]
async fn ssrf_guard_refuses_private_targets_when_not_allowed() {
    // A daemon with the default (strict) config.
    let dir = tempfile::TempDir::new().unwrap();
    let vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        PW.as_bytes(),
        KdfParams::insecure_for_tests(*b"ssrf-guard-salt!"),
    )
    .unwrap();
    let state = AppState::with(
        vault,
        Config::default(),
        Arc::new(|| 1_800_000_000),
        Arc::new(RecordingNotifier::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{base}/v1/vault/unseal"))
        .header("X-BSC-Client", "t")
        .json(&json!({ "passphrase": PW }))
        .send()
        .await
        .unwrap();
    let cookie = r
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let human = |m: Method, p: &str, b: Value| {
        http.request(m, format!("{base}{p}"))
            .header(header::COOKIE, &cookie)
            .header("X-BSC-Client", "t")
            .json(&b)
    };
    let sref: String = human(
        Method::POST,
        "/v1/items",
        json!({ "path": "p", "name": "n", "type": "api_key", "tags": [], "value": SECRET }),
    )
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap()["sref"]
        .as_str()
        .unwrap()
        .to_string();
    let tok: String = human(
        Method::POST,
        "/v1/tokens",
        json!({ "label": "b", "scope": { "paths": ["p"], "tags": [] } }),
    )
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap()["value"]
        .as_str()
        .unwrap()
        .to_string();
    // Strict mode: http:// patterns are refused outright.
    let r = human(
        Method::PUT,
        &format!("/v1/items/{sref}/use"),
        json!({ "binding": { "urls": ["http://api.example/*"], "header": "Authorization: Bearer {value}", "methods": ["GET"] } }),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "http pattern must be refused in strict mode"
    );
    human(Method::PUT, &format!("/v1/items/{sref}/use"), json!({ "binding": { "urls": ["https://127.0.0.1/*", "https://localhost/*", "https://10.0.0.5/*", "https://169.254.169.254/*"], "header": "Authorization: Bearer {value}", "methods": ["GET"] } })).send().await.unwrap();
    for url in [
        "https://127.0.0.1/admin",
        "https://localhost/x",
        "https://10.0.0.5/meta",
        "https://169.254.169.254/latest/meta-data",
    ] {
        let r = http
            .post(format!("{base}/v1/secrets/{sref}/use"))
            .bearer_auth(&tok)
            .json(&json!({ "reason": "probe", "url": url }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{url}");
        let v: Value = r.json().await.unwrap();
        assert_eq!(v["error"], "use_not_allowed", "{url}: {v}");
    }
}

#[tokio::test]
async fn happy_path_credential_reaches_upstream_and_never_the_agent() {
    let h = harness().await;
    let sref = h.item("api_key", SECRET).await;
    let tok = h.token(&["prod"]).await;
    let (s, v) = h
        .bind(
            &sref,
            &[&format!("{}/v1/*", h.up)],
            "Authorization: Bearer {value}",
            &["GET", "POST"],
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (s, v) = h.agent(&tok, Method::POST, &format!("/v1/secrets/{sref}/use"), Some(json!({
        "reason": "create charge for order 9",
        "url": format!("{}/v1/charges?x=1", h.up),
        "method": "POST",
        "headers": { "Authorization": "Bearer attacker-supplied", "Cookie": "evil=1", "X-Trace": "abc" },
        "body": "{\"amount\":100}"
    }))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["upstream_status"], 201);
    assert_eq!(v["upstream_headers"]["x-request-id"], "up-42");
    assert_eq!(v["body"], "{\"ok\":true,\"echo\":{\"amount\":100}}");
    assert!(
        !v.to_string().contains(SECRET),
        "the value must not be in the agent's response"
    );
    assert_eq!(v["truncated"], false);

    let auth = h.seen.auth.lock().unwrap().clone();
    assert_eq!(
        auth,
        vec![format!("Bearer {SECRET}")],
        "upstream saw the real credential, not the agent's header"
    );
    assert_eq!(
        h.seen.paths.lock().unwrap().clone(),
        vec!["/v1/charges".to_string()]
    );

    // Ledger: a use record with host+path and a read underneath, neither with the value.
    let (_, audit) = h
        .human(
            Method::GET,
            &format!("/v1/audit?subject={sref}&limit=100"),
            None,
        )
        .await;
    let recs = audit["records"].as_array().unwrap();
    let used = recs
        .iter()
        .find(|r| r["action"] == "secret_used")
        .expect("secret_used");
    assert_eq!(used["meta"]["method"], "POST");
    assert_eq!(used["meta"]["path"], "/v1/charges");
    assert_eq!(used["meta"]["reason"], "create charge for order 9");
    let read = recs
        .iter()
        .find(|r| r["action"] == "secret_read")
        .expect("secret_read");
    assert!(read["meta"]["reason"]
        .as_str()
        .unwrap()
        .starts_with("use_secret:"));
    for r in recs {
        assert!(!r.to_string().contains(SECRET));
    }
}

#[tokio::test]
async fn approval_required_item_pends_before_any_upstream_call() {
    let h = harness().await;
    let sref = h.item("service_account", "{\"k\":\"v\"}").await; // approval-required by default
    let tok = h.token(&["prod"]).await;
    h.bind(&sref, &[&format!("{}/*", h.up)], "X-Sa: {value}", &["GET"])
        .await;
    let (s, v) = h
        .agent(
            &tok,
            Method::POST,
            &format!("/v1/secrets/{sref}/use"),
            Some(json!({ "reason": "deploy", "url": format!("{}/deploy", h.up) })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["error"], "approval_pending");
    assert!(
        h.seen.auth.lock().unwrap().is_empty(),
        "no upstream call before approval"
    );
}

#[tokio::test]
async fn binary_values_cannot_be_used_in_a_header() {
    let h = harness().await;
    let (s, v) = h.human(Method::POST, "/v1/items", Some(json!({ "path": "prod/pay", "name": "blob", "type": "file", "tags": [], "value_base64": "AAEC/w==" }))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let sref = v["sref"].as_str().unwrap().to_string();
    let tok = h.token(&["prod"]).await;
    h.bind(
        &sref,
        &[&format!("{}/*", h.up)],
        "X-Blob: {value}",
        &["GET"],
    )
    .await;
    let (s, v) = h
        .agent(
            &tok,
            Method::POST,
            &format!("/v1/secrets/{sref}/use"),
            Some(json!({ "reason": "r", "url": format!("{}/x", h.up) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"], "use_not_allowed");
    assert!(h.seen.auth.lock().unwrap().is_empty());
}
