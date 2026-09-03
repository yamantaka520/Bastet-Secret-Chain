//! The MCP path must return the same JSON as the HTTP path, for successes and
//! for every error code it can reach. Otherwise the two would drift and the
//! `do_not` text an agent sees would depend on which door it used.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use bsc_crypto::kdf::KdfParams;
use bsc_daemon::{app, notify::RecordingNotifier, AppState, Config};
use bsc_mcp::McpServer;
use bsc_store::{
    access::{NewToken, Scope},
    model::{ItemType, NewItem},
    Actor, Vault,
};
use serde_json::{json, Value};

const T0: i64 = 1_800_000_000;

struct Fx {
    _dir: tempfile::TempDir,
    base: String,
    state: Arc<AppState>,
    clock: Arc<AtomicI64>,
}

async fn fixture() -> (Fx, String, String, String) {
    let dir = tempfile::TempDir::new().unwrap();
    let mut vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        b"pw",
        KdfParams::insecure_for_tests(*b"mcp-parity-salt!"),
    )
    .unwrap();
    // The daemon will run on a fixed clock; mint under the same clock so the
    // token is not born expired.
    let clock = Arc::new(AtomicI64::new(T0));
    let c0 = clock.clone();
    vault.set_clock(Box::new(move || c0.load(Ordering::SeqCst)));
    let human = Actor::Human {
        session: "s".into(),
    };
    let mk = |v: &mut Vault, path: &str, t: ItemType, body: &[u8]| {
        v.put(
            NewItem {
                path: path.into(),
                name: "n".into(),
                item_type: t,
                tags: vec![],
                env: None,
                approval_required: None,
                expires_at: None,
            },
            body,
            &human,
            "",
        )
        .unwrap()
    };
    let plain = mk(&mut vault, "prod/x", ItemType::ApiKey, b"plain-value");
    let guarded = mk(&mut vault, "prod/gcp", ItemType::ServiceAccount, b"guarded");
    let tok = vault
        .mint_token(
            NewToken {
                label: "mcp".into(),
                scope: Scope {
                    paths: vec!["prod".into()],
                    tags: vec![],
                },
                lifetime: 3600,
                max_lifetime: 86_400,
                max_reads: None,
                rate_limit_per_min: 600,
            },
            &human,
        )
        .unwrap();
    let token = tok.value.to_string();

    let c = clock.clone();
    let state = AppState::with(
        vault,
        Config::default(),
        Arc::new(move || c.load(Ordering::SeqCst)),
        Arc::new(RecordingNotifier::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(listener, app(st)).await.unwrap() });
    (
        Fx {
            _dir: dir,
            base: format!("http://{addr}"),
            state,
            clock,
        },
        token,
        plain,
        guarded,
    )
}

fn strip(mut v: Value) -> Value {
    if let Some(m) = v.as_object_mut() {
        m.remove("request_id");
    }
    v
}

async fn http_get(base: &str, token: &str, path: &str, reason: Option<&str>) -> (u16, Value) {
    let c = reqwest::Client::new();
    let mut r = c.get(format!("{base}{path}")).bearer_auth(token);
    if let Some(reason) = reason {
        r = r.header("X-BSC-Reason", reason);
    }
    let resp = r.send().await.unwrap();
    (resp.status().as_u16(), strip(resp.json().await.unwrap()))
}

async fn call(m: &McpServer, name: &str, args: Value) -> (bool, Value) {
    let out = m.call_tool(name, &args).await;
    assert!(out["content"][0]["text"].is_string());
    let text: Value = serde_json::from_str(out["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        text, out["structuredContent"],
        "text and structured content must agree"
    );
    (
        out["isError"].as_bool().unwrap(),
        strip(out["structuredContent"].clone()),
    )
}

#[tokio::test]
async fn tools_list_is_exactly_the_read_only_six_with_safety_text() {
    let m = McpServer::new("http://127.0.0.1:1", "bsct_x");
    let resp = m
        .handle(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .await
        .unwrap();
    let tools = resp["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "list_secrets",
            "get_secret",
            "request_access",
            "check_access",
            "use_secret",
            "renew_access"
        ]
    );
    for t in tools {
        assert!(
            !t["name"].as_str().unwrap().contains("create")
                && !t["name"].as_str().unwrap().contains("delete")
        );
    }
    let desc = tools[1]["description"].as_str().unwrap();
    for must in [
        "LIVE SECRET",
        "do not paste it into chat",
        "approval_pending",
        "reason",
    ] {
        assert!(
            desc.contains(must),
            "get_secret description missing {must:?}"
        );
    }
    assert_eq!(
        tools[1]["inputSchema"]["required"],
        json!(["sref", "reason"])
    );
    let use_desc = tools[4]["description"].as_str().unwrap();
    assert!(
        use_desc.contains("WITHOUT seeing it") && use_desc.contains("never ask the user to paste")
    );
    assert_eq!(
        tools[4]["inputSchema"]["required"],
        json!(["sref", "reason", "url"])
    );
}

#[tokio::test]
async fn initialize_ping_and_unknown_method() {
    let m = McpServer::new("http://127.0.0.1:1", "bsct_x");
    let init = m
        .handle(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-03-26", "capabilities": {} } }))
        .await
        .unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init["result"]["serverInfo"]["name"], "bsc");
    assert!(init["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("paste"));
    assert!(m
        .handle(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await
        .is_none());
    assert_eq!(
        m.handle(json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }))
            .await
            .unwrap()["result"],
        json!({})
    );
    let e = m
        .handle(json!({ "jsonrpc": "2.0", "id": 3, "method": "resources/list" }))
        .await
        .unwrap();
    assert_eq!(e["error"]["code"], -32601);
}

#[tokio::test]
async fn daemon_unreachable_speaks_the_contract() {
    let m = McpServer::new("http://127.0.0.1:1", "bsct_x");
    let (is_err, v) = call(&m, "get_secret", json!({ "sref": "sref_x", "reason": "r" })).await;
    assert!(is_err);
    assert_eq!(v["error"], "daemon_unreachable");
    assert!(v["do_not"].as_str().unwrap().contains("paste"));
    assert!(v["next_action"].as_str().unwrap().contains("bsc serve"));
}

#[tokio::test]
async fn mcp_and_http_return_identical_json_for_success_and_every_reachable_error() {
    let (fx, token, plain, guarded) = fixture().await;
    let m = McpServer::new(&fx.base, &token);

    // success
    let (is_err, mcp) = call(
        &m,
        "get_secret",
        json!({ "sref": plain, "reason": "compare" }),
    )
    .await;
    let (status, http) = http_get(
        &fx.base,
        &token,
        &format!("/v1/secrets/{plain}"),
        Some("compare"),
    )
    .await;
    assert!(!is_err);
    assert_eq!(status, 200);
    assert_eq!(mcp, http);
    assert_eq!(mcp["value"], "plain-value");

    // list
    let (_, mcp) = call(&m, "list_secrets", json!({})).await;
    let (_, http) = http_get(&fx.base, &token, "/v1/secrets", None).await;
    assert_eq!(mcp, http);
    assert_eq!(mcp["items"].as_array().unwrap().len(), 2);
    assert!(!mcp.to_string().contains("plain-value"));

    // reason_required
    let (is_err, mcp) = call(&m, "get_secret", json!({ "sref": plain, "reason": "  " })).await;
    let (_, http) = http_get(
        &fx.base,
        &token,
        &format!("/v1/secrets/{plain}"),
        Some("  "),
    )
    .await;
    assert!(is_err);
    assert_eq!(mcp, http);
    assert_eq!(mcp["error"], "reason_required");

    // not_found
    let (_, mcp) = call(
        &m,
        "get_secret",
        json!({ "sref": "sref_nope", "reason": "r" }),
    )
    .await;
    let (_, http) = http_get(&fx.base, &token, "/v1/secrets/sref_nope", Some("r")).await;
    assert_eq!(mcp, http);
    assert_eq!(mcp["error"], "not_found");

    // approval_pending is not flagged as an error, and matches HTTP.
    let (is_err, mcp) = call(
        &m,
        "get_secret",
        json!({ "sref": guarded, "reason": "deploy" }),
    )
    .await;
    assert!(!is_err, "202 is a wait, not a failure");
    assert_eq!(mcp["error"], "approval_pending");
    let apr = mcp["approval_id"].as_str().unwrap().to_string();
    let (status, http) = http_get(
        &fx.base,
        &token,
        &format!("/v1/secrets/{guarded}"),
        Some("deploy"),
    )
    .await;
    assert_eq!(status, 202);
    assert_eq!(mcp, http, "same pending request, same body");

    // check_access pending, then approve, then value once.
    let (is_err, v) = call(
        &m,
        "check_access",
        json!({ "approval_id": apr, "wait_seconds": 0 }),
    )
    .await;
    assert!(!is_err);
    assert_eq!(v["status"], "pending");
    fx.state
        .vault()
        .decide_approval(
            &apr,
            true,
            1800,
            &Actor::Human {
                session: "ui".into(),
            },
        )
        .unwrap();
    let (_, v) = call(&m, "check_access", json!({ "approval_id": apr })).await;
    assert_eq!(v["status"], "approved");
    assert_eq!(v["value"], "guarded");
    let (_, v) = call(&m, "check_access", json!({ "approval_id": apr })).await;
    assert_eq!(v["status"], "consumed");

    // use_secret without a binding: use_not_configured, identical to HTTP.
    let (is_err, mcp) = call(
        &m,
        "use_secret",
        json!({ "sref": plain, "reason": "r", "url": "https://api.example/x" }),
    )
    .await;
    assert!(is_err);
    assert_eq!(mcp["error"], "use_not_configured");
    let http_r = reqwest::Client::new()
        .post(format!("{}/v1/secrets/{plain}/use", fx.base))
        .bearer_auth(&token)
        .json(&json!({ "reason": "r", "url": "https://api.example/x", "method": "GET" }))
        .send()
        .await
        .unwrap();
    assert_eq!(http_r.status().as_u16(), 400);
    let http: Value = strip(http_r.json().await.unwrap());
    assert_eq!(mcp, http);

    // renew_access outside the window: invalid_request, same as HTTP.
    let (is_err, mcp) = call(&m, "renew_access", json!({})).await;
    assert!(is_err);
    assert_eq!(mcp["error"], "invalid_request");

    // token_expired renewable, then renew succeeds via MCP, then read works.
    fx.clock.fetch_add(3600, Ordering::SeqCst);
    let (is_err, mcp) = call(&m, "get_secret", json!({ "sref": plain, "reason": "r" })).await;
    let (_, http) = http_get(&fx.base, &token, &format!("/v1/secrets/{plain}"), Some("r")).await;
    assert!(is_err);
    assert_eq!(mcp, http);
    assert_eq!(mcp["error"], "token_expired");
    assert_eq!(mcp["renewable"], true);
    let (is_err, _) = call(&m, "renew_access", json!({})).await;
    assert!(!is_err);
    let (is_err, _) = call(&m, "get_secret", json!({ "sref": plain, "reason": "r" })).await;
    assert!(!is_err);

    // vault_sealed
    fx.state.vault().seal(&Actor::System).unwrap();
    let (is_err, mcp) = call(&m, "get_secret", json!({ "sref": plain, "reason": "r" })).await;
    let (_, http) = http_get(&fx.base, &token, &format!("/v1/secrets/{plain}"), Some("r")).await;
    assert!(is_err);
    assert_eq!(mcp, http);
    assert_eq!(mcp["error"], "vault_sealed");
    assert!(mcp["do_not"].as_str().unwrap().contains("passphrase"));
}

#[tokio::test]
async fn bad_tool_arguments_are_local_contract_errors() {
    let m = McpServer::new("http://127.0.0.1:1", "bsct_x");
    let (is_err, v) = call(&m, "get_secret", json!({ "reason": "r" })).await;
    assert!(is_err);
    assert_eq!(v["error"], "invalid_request");
    let (is_err, v) = call(&m, "nope", json!({})).await;
    assert!(is_err);
    assert_eq!(v["error"], "unknown_tool");
}
