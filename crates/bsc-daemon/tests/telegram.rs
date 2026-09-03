//! Telegram approval channel against a mock Bot API: outbound only, bound to
//! one chat, no buttons for local-only items, decisions in the ledger.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc, Mutex,
};

use axum::{extract::State as AxState, routing::post, Json, Router};
use bsc_crypto::kdf::KdfParams;
use bsc_daemon::{
    app,
    notify::{ChannelNotifier, RecordingNotifier},
    telegram::{Telegram, TelegramConfig},
    AppState, Config,
};
use bsc_store::Vault;
use reqwest::{header, Method, StatusCode};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const PW: &str = "correct horse battery staple";
const CHAT: i64 = -1001234567890;
const ALICE: i64 = 777;
const MALLORY: i64 = 666;

#[derive(Default)]
struct BotApi {
    sent: Mutex<Vec<Value>>,
    edits: Mutex<Vec<Value>>,
    acks: Mutex<Vec<Value>>,
}

async fn mock_bot(api: Arc<BotApi>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/bot:token/sendMessage",
            post(
                |AxState(a): AxState<Arc<BotApi>>, Json(b): Json<Value>| async move {
                    a.sent.lock().unwrap().push(b);
                    Json(json!({ "ok": true, "result": { "message_id": 1 } }))
                },
            ),
        )
        .route(
            "/bot:token/editMessageText",
            post(
                |AxState(a): AxState<Arc<BotApi>>, Json(b): Json<Value>| async move {
                    a.edits.lock().unwrap().push(b);
                    Json(json!({ "ok": true, "result": {} }))
                },
            ),
        )
        .route(
            "/bot:token/answerCallbackQuery",
            post(
                |AxState(a): AxState<Arc<BotApi>>, Json(b): Json<Value>| async move {
                    a.acks.lock().unwrap().push(b);
                    Json(json!({ "ok": true, "result": true }))
                },
            ),
        )
        .with_state(api);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

struct H {
    _dir: tempfile::TempDir,
    base: String,
    http: reqwest::Client,
    cookie: String,
    state: Arc<AppState>,
    clock: Arc<AtomicI64>,
    bot: Arc<BotApi>,
    tg: Arc<Telegram>,
    rx: Option<tokio::sync::mpsc::UnboundedReceiver<bsc_daemon::notify::Escalation>>,
}

async fn harness(allowed: Vec<i64>) -> H {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        PW.as_bytes(),
        KdfParams::insecure_for_tests(*b"telegram-salt-01"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let c = clock.clone();
    let (notifier, rx) = ChannelNotifier::new(Arc::new(RecordingNotifier::default()));
    let state = AppState::with(
        vault,
        Config::default(),
        Arc::new(move || c.load(Ordering::SeqCst)),
        notifier,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(listener, app(st)).await.unwrap() });
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
    let bot = Arc::new(BotApi::default());
    let api_base = mock_bot(bot.clone()).await;
    let tg = Arc::new(Telegram::new(
        TelegramConfig {
            api_base,
            token: Arc::new(Zeroizing::new("123:TESTTOKEN".into())),
            chat_id: CHAT,
            allowed_users: allowed,
            external_step: 3,
        },
        state.clone(),
    ));
    H {
        _dir: dir,
        base,
        http,
        cookie,
        state,
        clock,
        bot,
        tg,
        rx: Some(rx),
    }
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
            .header("X-BSC-Reason", "deploy build 7")
            .send()
            .await
            .unwrap();
        (resp.status(), resp.json().await.unwrap_or(Value::Null))
    }
    async fn setup(&self, local_only: bool) -> (String, String) {
        let (_, v) = self.human(Method::POST, "/v1/items", Some(json!({ "path": "prod/gcp", "name": "firebase-admin", "type": "service_account", "tags": [], "value": "{\"sa\":1}" }))).await;
        let sref = v["sref"].as_str().unwrap().to_string();
        if local_only {
            self.human(
                Method::PATCH,
                &format!("/v1/items/{sref}"),
                Some(json!({ "local_approval_only": true })),
            )
            .await;
        }
        let (_, v) = self
            .human(
                Method::POST,
                "/v1/tokens",
                Some(json!({ "label": "deploy-bot", "scope": { "paths": ["prod"], "tags": [] } })),
            )
            .await;
        (sref, v["value"].as_str().unwrap().to_string())
    }
    /// Advance to the external step and push escalations through the channel.
    async fn escalate_to_external(&mut self) {
        self.clock.fetch_add(60, Ordering::SeqCst);
        self.state.tick();
        let rx = self.rx.as_mut().unwrap();
        while let Ok(e) = rx.try_recv() {
            self.tg.deliver(&e).await;
        }
    }
    fn callback(&self, from: i64, chat: i64, data: &str) -> Value {
        json!({ "update_id": 1, "callback_query": { "id": "cq1", "from": { "id": from }, "message": { "message_id": 1, "chat": { "id": chat }, "text": "orig" }, "data": data } })
    }
}

#[tokio::test]
async fn escalation_reaches_telegram_only_at_the_external_step_with_buttons() {
    let mut h = harness(vec![]).await;
    let (sref, tok) = h.setup(false).await;
    let (s, v) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let apr = v["approval_id"].as_str().unwrap().to_string();

    // Steps 1 and 2 (0 s, 20 s) must not leave the machine.
    let rx = h.rx.as_mut().unwrap();
    while let Ok(e) = rx.try_recv() {
        h.tg.deliver(&e).await;
    }
    h.clock.fetch_add(20, Ordering::SeqCst);
    h.state.tick();
    let rx = h.rx.as_mut().unwrap();
    while let Ok(e) = rx.try_recv() {
        h.tg.deliver(&e).await;
    }
    assert!(
        h.bot.sent.lock().unwrap().is_empty(),
        "nothing external before step 3"
    );

    h.escalate_to_external().await;
    let sent = h.bot.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let m = &sent[0];
    assert_eq!(m["chat_id"], CHAT);
    let text = m["text"].as_str().unwrap();
    assert!(
        text.contains("deploy-bot")
            && text.contains("firebase-admin")
            && text.contains("deploy build 7")
            && text.contains(&apr),
        "{text}"
    );
    assert!(
        !text.contains("{\"sa\":1}"),
        "no secret material in the message"
    );
    let buttons = &m["reply_markup"]["inline_keyboard"][0];
    assert_eq!(buttons[0]["callback_data"], format!("approve:{apr}"));
    assert_eq!(buttons[1]["callback_data"], format!("deny:{apr}"));

    // The ledger shows the notification.
    let (_, audit) = h
        .human(
            Method::GET,
            &format!("/v1/audit?subject={sref}&limit=100"),
            None,
        )
        .await;
    let n = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "approval_notified")
        .expect("approval_notified");
    assert_eq!(n["meta"]["channel"], "telegram");
    assert_eq!(n["meta"]["buttons"], true);
}

#[tokio::test]
async fn approve_button_from_the_bound_chat_decides_and_is_attributed_externally() {
    let mut h = harness(vec![ALICE]).await;
    let (sref, tok) = h.setup(false).await;
    let (_, v) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    let apr = v["approval_id"].as_str().unwrap().to_string();
    h.escalate_to_external().await;

    // Wrong chat: ignored, nothing decided.
    let ack =
        h.tg.handle_update(&h.callback(ALICE, 42, &format!("approve:{apr}")))
            .await;
    assert_eq!(ack.as_deref(), Some("unbound chat"));
    // Non-allowed user in the right chat: refused.
    let ack =
        h.tg.handle_update(&h.callback(MALLORY, CHAT, &format!("approve:{apr}")))
            .await;
    assert_eq!(ack.as_deref(), Some("not allowed"));
    let (s, _) = h.agent(&tok, &format!("/v1/access-requests/{apr}")).await;
    assert_eq!(s, StatusCode::OK, "still pending");

    // Allowed user approves.
    let ack =
        h.tg.handle_update(&h.callback(ALICE, CHAT, &format!("approve:{apr}")))
            .await
            .unwrap();
    assert!(ack.starts_with("✅"), "{ack}");
    assert_eq!(
        h.bot.acks.lock().unwrap().len(),
        2,
        "one refusal alert + one ack"
    );
    assert_eq!(
        h.bot.edits.lock().unwrap().len(),
        1,
        "message edited to show the decision"
    );

    let (s, v) = h.agent(&tok, &format!("/v1/access-requests/{apr}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "approved");
    assert_eq!(v["value"], "{\"sa\":1}");

    let (_, audit) = h
        .human(
            Method::GET,
            &format!("/v1/audit?subject={sref}&limit=100"),
            None,
        )
        .await;
    let d = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "approval_decided")
        .unwrap();
    assert_eq!(d["actor"], format!("external:telegram:{ALICE}"));
    assert_eq!(d["outcome"], "approved");

    // A second press on the same request is refused (already decided).
    let ack =
        h.tg.handle_update(&h.callback(ALICE, CHAT, &format!("deny:{apr}")))
            .await
            .unwrap();
    assert!(ack.starts_with("無法決定"), "{ack}");
}

#[tokio::test]
async fn deny_button_denies() {
    let mut h = harness(vec![]).await;
    let (sref, tok) = h.setup(false).await;
    let (_, v) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    let apr = v["approval_id"].as_str().unwrap().to_string();
    h.escalate_to_external().await;
    let ack =
        h.tg.handle_update(&h.callback(ALICE, CHAT, &format!("deny:{apr}")))
            .await
            .unwrap();
    assert!(ack.starts_with("⛔"), "{ack}");
    let (s, v) = h.agent(&tok, &format!("/v1/access-requests/{apr}")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["error"], "approval_denied");
}

#[tokio::test]
async fn local_only_items_are_announced_without_buttons_and_cannot_be_decided_remotely() {
    let mut h = harness(vec![]).await;
    let (sref, tok) = h.setup(true).await;
    let (_, v) = h.agent(&tok, &format!("/v1/secrets/{sref}")).await;
    let apr = v["approval_id"].as_str().unwrap().to_string();
    h.escalate_to_external().await;
    let sent = h.bot.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].get("reply_markup").is_none(),
        "no buttons for local-only: {}",
        sent[0]
    );
    assert!(sent[0]["text"].as_str().unwrap().contains("僅限本機核准"));
    // Even a forged button press for it is refused.
    let ack =
        h.tg.handle_update(&h.callback(ALICE, CHAT, &format!("approve:{apr}")))
            .await
            .unwrap();
    assert!(ack.contains("僅限本機核准"), "{ack}");
    let (s, _) = h.agent(&tok, &format!("/v1/access-requests/{apr}")).await;
    assert_eq!(s, StatusCode::OK, "still pending");
}
