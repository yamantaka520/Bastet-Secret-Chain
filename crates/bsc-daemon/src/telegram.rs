//! Telegram as an outbound external approval channel (ADR 0005 §4).
//!
//! The daemon **initiates** every connection: `sendMessage` for escalations
//! that reached the external step, and a `getUpdates` long-poll for the
//! Approve / Deny button presses. No inbound port is opened. A message never
//! carries secret material — item label, token label, the agent's reason,
//! the deadline — and never a link that alone releases anything. Decisions are
//! accepted only from the one configured chat (and, if given, the allowed
//! user ids), and items flagged `local_approval_only` are announced without
//! buttons.
//!
//! Every decision taken here lands in the ledger as
//! `external:telegram:<user id>`, so the chain shows which channel and which
//! account approved what.

use std::{sync::Arc, time::Duration};

use bsc_store::Actor;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{notify::Escalation, state::AppState};

/// Static configuration for the channel.
#[derive(Clone)]
pub struct TelegramConfig {
    /// `https://api.telegram.org` in production; tests point at a mock.
    pub api_base: String,
    /// Bot token. Read from a credential or a 0600 file; never logged.
    pub token: Arc<Zeroizing<String>>,
    /// The one chat whose buttons are honoured.
    pub chat_id: i64,
    /// If non-empty, only these Telegram user ids may decide.
    pub allowed_users: Vec<i64>,
    /// Ladder step at which to send externally (1-based). ADR 0005: step 3.
    pub external_step: u32,
}

impl std::fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramConfig")
            .field("api_base", &self.api_base)
            .field("chat_id", &self.chat_id)
            .field("allowed_users", &self.allowed_users)
            .field("external_step", &self.external_step)
            .finish_non_exhaustive()
    }
}

/// The running channel.
pub struct Telegram {
    cfg: TelegramConfig,
    http: reqwest::Client,
    state: Arc<AppState>,
}

impl Telegram {
    /// Build the channel for a daemon state.
    pub fn new(cfg: TelegramConfig, state: Arc<AppState>) -> Telegram {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(40))
            .user_agent(concat!("bsc/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        Telegram { cfg, http, state }
    }

    fn url(&self, method: &str) -> String {
        format!(
            "{}/bot{}/{method}",
            self.cfg.api_base.trim_end_matches('/'),
            self.cfg.token.as_str()
        )
    }

    async fn call(&self, method: &str, body: Value) -> Result<Value, String> {
        let r = self
            .http
            .post(self.url(method))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("telegram {method}: {e}"))?;
        let v: Value = r
            .json()
            .await
            .map_err(|e| format!("telegram {method}: bad json: {e}"))?;
        if v["ok"].as_bool() != Some(true) {
            return Err(format!(
                "telegram {method}: {}",
                v["description"].as_str().unwrap_or("not ok")
            ));
        }
        Ok(v["result"].clone())
    }

    /// Message text for an escalation. Deliberately plain: no markdown that a
    /// reason string could break out of.
    pub fn text_for(e: &Escalation, now: i64) -> String {
        let item = e.item_name.clone().unwrap_or_else(|| e.item_id.clone());
        let who = e.token_label.clone().unwrap_or_else(|| e.token_id.clone());
        let left = (e.expires_at - now).max(0);
        let mut s = format!(
            "🔐 Bastet Secret Chain — 需要核准\n\n🤖 {who}\n想讀取 {item}\n\n理由：「{}」\n\n⏳ {left} 秒後自動拒絕 · {}",
            one_line(&e.reason, 300),
            e.approval_id
        );
        if e.local_only {
            s.push_str("\n\n🏠 此項目僅限本機核准：請在保險庫 UI 決定，這裡不提供按鈕。");
        }
        s
    }

    /// Deliver one escalation, if it has reached the external step.
    pub async fn deliver(&self, e: &Escalation) {
        if e.step < self.cfg.external_step {
            return;
        }
        let text = Self::text_for(e, self.state.now());
        let mut body =
            json!({ "chat_id": self.cfg.chat_id, "text": text, "disable_web_page_preview": true });
        if !e.local_only {
            body["reply_markup"] = json!({ "inline_keyboard": [[
                { "text": "✅ 核准", "callback_data": format!("approve:{}", e.approval_id) },
                { "text": "⛔ 拒絕", "callback_data": format!("deny:{}", e.approval_id) }
            ]] });
        }
        match self.call("sendMessage", body).await {
            Ok(_) => {
                let v = self.state.vault();
                let _ = v.audit_event(
                    &Actor::System,
                    "approval_notified",
                    Some(&e.item_id),
                    "ok",
                    json!({ "approval_id": e.approval_id, "channel": "telegram", "step": e.step, "buttons": !e.local_only }),
                );
            }
            Err(err) => {
                tracing::warn!(error = %err, approval = %e.approval_id, "telegram delivery failed")
            }
        }
    }

    /// Handle one update from `getUpdates`. Returns the acknowledgement text,
    /// or `None` if the update was not a callback for us.
    pub async fn handle_update(&self, u: &Value) -> Option<String> {
        let cq = u.get("callback_query")?;
        let from_id = cq["from"]["id"].as_i64()?;
        let chat_id = cq["message"]["chat"]["id"].as_i64()?;
        let data = cq["data"].as_str()?;
        let cq_id = cq["id"].as_str().unwrap_or("").to_string();
        let msg_id = cq["message"]["message_id"].as_i64();

        if chat_id != self.cfg.chat_id {
            tracing::warn!(chat_id, "telegram callback from an unbound chat ignored");
            return Some("unbound chat".into());
        }
        if !self.cfg.allowed_users.is_empty() && !self.cfg.allowed_users.contains(&from_id) {
            tracing::warn!(from_id, "telegram callback from a non-allowed user ignored");
            let _ = self
                .call(
                    "answerCallbackQuery",
                    json!({ "callback_query_id": cq_id, "text": "你不在核准名單中", "show_alert": true }),
                )
                .await;
            return Some("not allowed".into());
        }
        let (approve, apr) = if let Some(id) = data.strip_prefix("approve:") {
            (true, id)
        } else if let Some(id) = data.strip_prefix("deny:") {
            (false, id)
        } else {
            return Some("unknown action".into());
        };

        let actor = Actor::External {
            channel: "telegram".into(),
            id: from_id.to_string(),
        };
        let outcome: Result<String, String> = {
            let mut v = self.state.vault();
            match v.approval(apr) {
                Ok(a)
                    if v.detail(&a.item_id)
                        .map(|d| d.meta.local_approval_only)
                        .unwrap_or(true) =>
                {
                    Err("此項目僅限本機核准".to_string())
                }
                Ok(_) => v
                    .decide_approval(apr, approve, self.state.config.grant_ttl, &actor)
                    .map(|a| a.status.as_str().to_string())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        };
        let ack = match &outcome {
            Ok(status) => format!(
                "{} · {status}",
                if approve {
                    "✅ 已核准"
                } else {
                    "⛔ 已拒絕"
                }
            ),
            Err(e) => format!("無法決定：{e}"),
        };
        let _ = self
            .call(
                "answerCallbackQuery",
                json!({ "callback_query_id": cq_id, "text": ack }),
            )
            .await;
        if let Some(mid) = msg_id {
            let original = cq["message"]["text"].as_str().unwrap_or("");
            let _ = self
                .call(
                    "editMessageText",
                    json!({ "chat_id": chat_id, "message_id": mid, "text": format!("{original}\n\n— {ack}（by {from_id}）") }),
                )
                .await;
        }
        Some(ack)
    }

    /// Run forever: deliver escalations from `rx` and long-poll for buttons.
    pub async fn run(self: Arc<Self>, mut rx: tokio::sync::mpsc::UnboundedReceiver<Escalation>) {
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                me.deliver(&e).await;
            }
        });
        let mut offset: i64 = 0;
        loop {
            match self
                .call(
                    "getUpdates",
                    json!({ "timeout": 25, "offset": offset, "allowed_updates": ["callback_query"] }),
                )
                .await
            {
                Ok(Value::Array(updates)) => {
                    for u in updates {
                        if let Some(id) = u["update_id"].as_i64() {
                            offset = offset.max(id + 1);
                        }
                        self.handle_update(&u).await;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "telegram poll failed; backing off");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}

fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > max {
        format!("{}…", flat.chars().take(max - 1).collect::<String>())
    } else {
        flat
    }
}
