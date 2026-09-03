//! The error contract (`docs/API_CONTRACT.md` §4).
//!
//! Every non-2xx body — and the `202 approval_pending` body, which is not an
//! error but shares the shape — carries a machine code plus two pieces of
//! prose the agent will act on: `next_action` and `do_not`. The `do_not` text
//! is the single most important string in the system; it is what stands
//! between a confused agent and a request to paste a cloud key into a chat.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Map, Value};

use crate::util::{request_id, rfc3339};

/// A contract error. Build with the constructors; do not fill fields by hand.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// Stable code from the contract table.
    pub code: &'static str,
    /// HTTP status.
    pub status: StatusCode,
    /// One human sentence.
    pub message: String,
    /// What the agent should do now.
    pub next_action: String,
    /// What the agent must not do.
    pub do_not: &'static str,
    /// Seconds, when a retry makes sense.
    pub retry_after: Option<u64>,
    /// UI fragment for the deep link.
    pub ui: Option<&'static str>,
    /// Code-specific extra fields.
    pub extra: Map<String, Value>,
}

const DO_NOT_PASTE: &str = "Do not ask the user to paste the secret into the conversation. Do not substitute another token. Do not continue without the credential.";

impl ApiError {
    fn new(
        code: &'static str,
        status: StatusCode,
        message: impl Into<String>,
        next_action: impl Into<String>,
        do_not: &'static str,
    ) -> Self {
        ApiError {
            code,
            status,
            message: message.into(),
            next_action: next_action.into(),
            do_not,
            retry_after: None,
            ui: None,
            extra: Map::new(),
        }
    }

    fn with(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }

    fn ui(mut self, fragment: &'static str) -> Self {
        self.ui = Some(fragment);
        self
    }

    // ---------------------------------------------------------- agent codes

    /// 401 — the token is past `expires_at`.
    pub fn token_expired(expires_at: i64, renewable: bool) -> Self {
        let next = if renewable {
            "Call renew_access (POST /v1/token/renew) with this same token. If that is refused, call request_access with a reason; a human will approve within 5 minutes."
        } else {
            "This token can no longer be renewed. Tell the user it must be re-issued in the vault UI, then stop."
        };
        Self::new(
            "token_expired",
            StatusCode::UNAUTHORIZED,
            "The token has expired.",
            next,
            DO_NOT_PASTE,
        )
        .with("expired_at", json!(rfc3339(expires_at)))
        .with("renewable", json!(renewable))
        .ui("#/tokens")
    }

    /// 401 — revoked by a human.
    pub fn token_revoked() -> Self {
        Self::new(
            "token_revoked",
            StatusCode::UNAUTHORIZED,
            "The token was revoked.",
            "Stop. Tell the user this token was revoked and needs re-issuing in the vault UI.",
            "Do not retry. Do not look for another credential source. Do not ask the user to paste the secret.",
        )
        .ui("#/tokens")
    }

    /// 401 — no token, or one the vault does not recognize.
    pub fn unauthorized() -> Self {
        Self::new(
            "unauthorized",
            StatusCode::UNAUTHORIZED,
            "No valid credential was presented.",
            "Tell the user the vault did not recognize this token; they should check the MCP server or client configuration.",
            "Do not guess or fabricate a token. Do not ask the user to paste a secret or a passphrase into the conversation.",
        )
    }

    /// 403 — the item exists but is outside the token's scope.
    pub fn scope_mismatch() -> Self {
        Self::new(
            "scope_mismatch",
            StatusCode::FORBIDDEN,
            "This token does not cover that item.",
            "Tell the user this token does not cover the item; they can widen the scope or mint another token in the vault UI.",
            "Do not try other references to find one that works. Do not ask the user to paste the secret.",
        )
        .ui("#/tokens")
    }

    /// 202 — a human has been asked. Not an error, but the same shape.
    pub fn approval_pending(approval_id: &str, expires_at: i64, retry_after: u64) -> Self {
        let mut e = Self::new(
            "approval_pending",
            StatusCode::ACCEPTED,
            "A human has been notified and must approve this read.",
            format!("Poll check_access (GET /v1/access-requests/{approval_id}) every {retry_after} seconds until the status is approved, denied, or timeout."),
            "Do not ask the user to paste the secret into the conversation. Do not repeat the original request in a loop. Do not use a different token.",
        )
        .with("status", json!("approval_pending"))
        .with("approval_id", json!(approval_id))
        .with("expires_at", json!(rfc3339(expires_at)))
        .ui("#/approvals");
        e.retry_after = Some(retry_after);
        e
    }

    /// 403 — the human said no.
    pub fn approval_denied() -> Self {
        Self::new(
            "approval_denied",
            StatusCode::FORBIDDEN,
            "A human denied this read.",
            "Stop this step. Report the denial to the user, including the reason you gave.",
            "Do not re-request with a different reason. Do not ask the user to paste the secret.",
        )
        .ui("#/approvals")
    }

    /// 408 — nobody answered.
    pub fn approval_timeout() -> Self {
        Self::new(
            "approval_timeout",
            StatusCode::REQUEST_TIMEOUT,
            "No human responded before the deadline.",
            "Report it and stop, or ask the user to approve in the vault UI and then retry once.",
            "Do not loop. Do not ask the user to paste the secret.",
        )
        .ui("#/approvals")
    }

    /// 429 — read budget spent.
    pub fn quota_exhausted() -> Self {
        Self::new(
            "quota_exhausted",
            StatusCode::TOO_MANY_REQUESTS,
            "This token's read budget is spent.",
            "Tell the user; a human can mint a token with a larger budget in the vault UI.",
            "Do not retry. Do not ask the user to paste the secret.",
        )
        .ui("#/tokens")
    }

    /// 429 — too fast.
    pub fn rate_limited(retry_after: u64) -> Self {
        let mut e = Self::new(
            "rate_limited",
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests from this token.",
            format!("Wait {retry_after} seconds, then retry once."),
            "Do not tighten the loop. Do not open parallel requests.",
        );
        e.retry_after = Some(retry_after);
        e
    }

    /// 503 — the vault is locked.
    pub fn vault_sealed() -> Self {
        Self::new(
            "vault_sealed",
            StatusCode::SERVICE_UNAVAILABLE,
            "The vault is sealed.",
            "Tell the user the vault is locked and must be unsealed in the vault UI, then retry once.",
            "Do not ask the user for the vault passphrase — it is entered in the UI, never in chat. Do not ask the user to paste the secret.",
        )
        .ui("#/vault")
    }

    /// 404.
    pub fn not_found(what: &str) -> Self {
        Self::new(
            "not_found",
            StatusCode::NOT_FOUND,
            format!("{what} not found."),
            "Check the reference with list_secrets (GET /v1/secrets).",
            "Do not guess references.",
        )
    }

    /// 400 — `reason` missing or blank.
    pub fn reason_required() -> Self {
        Self::new(
            "reason_required",
            StatusCode::BAD_REQUEST,
            "A reason is required to release a value.",
            "Repeat the call with a concrete reason: what you are about to do with the credential. It is shown to the approving human and recorded.",
            "Do not use a placeholder reason.",
        )
    }

    /// 400.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(
            "invalid_request",
            StatusCode::BAD_REQUEST,
            message,
            "Fix the request as described in message.",
            "Do not work around the validation.",
        )
    }

    /// 403 — feature off.
    pub fn handoff_disabled() -> Self {
        Self::new(
            "handoff_disabled",
            StatusCode::FORBIDDEN,
            "Handoff links are disabled on this vault.",
            "Use a token instead; a human can mint one in the vault UI.",
            "Do not ask the user to paste the secret.",
        )
    }

    // ---------------------------------------------------------- human codes

    /// 401 — passphrase rejected.
    pub fn bad_passphrase() -> Self {
        Self::new(
            "bad_passphrase",
            StatusCode::UNAUTHORIZED,
            "The passphrase was rejected.",
            "Enter the passphrase again in the vault UI.",
            "Do not send the passphrase anywhere but the unseal endpoint.",
        )
    }

    /// 403 — a browser request from a foreign origin, or missing the client header.
    pub fn forbidden_origin() -> Self {
        Self::new(
            "forbidden_origin",
            StatusCode::FORBIDDEN,
            "Cross-origin request refused.",
            "Use the vault UI served by this daemon.",
            "—",
        )
    }

    /// 500 — something we did not expect. The message is generic on purpose.
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "internal error");
        Self::new(
            "internal",
            StatusCode::INTERNAL_SERVER_ERROR,
            "The daemon hit an internal error.",
            "Retry once. If it repeats, tell the user to check the daemon log.",
            "Do not ask the user to paste the secret.",
        )
    }

    /// Body as the contract specifies, without the request id.
    pub fn body(&self) -> Value {
        let mut m = Map::new();
        m.insert("error".into(), json!(self.code));
        m.insert("message".into(), json!(self.message));
        m.insert("next_action".into(), json!(self.next_action));
        m.insert("do_not".into(), json!(self.do_not));
        if let Some(r) = self.retry_after {
            m.insert("retry_after".into(), json!(r));
        }
        if let Some(ui) = self.ui {
            m.insert("ui".into(), json!(ui));
        }
        for (k, v) in &self.extra {
            m.insert(k.clone(), v.clone());
        }
        Value::Object(m)
    }
}

impl From<bsc_store::StoreError> for ApiError {
    fn from(e: bsc_store::StoreError) -> Self {
        use bsc_store::StoreError as S;
        match e {
            S::Sealed => ApiError::vault_sealed(),
            S::NotFound => ApiError::not_found("Item"),
            S::BadPassphrase => ApiError::bad_passphrase(),
            S::Invalid(msg) => ApiError::invalid_request(msg),
            other => ApiError::internal(other),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = self.body();
        let rid = request_id();
        if let Value::Object(m) = &mut body {
            m.insert("request_id".into(), json!(rid));
        }
        let mut resp = (self.status, Json(body)).into_response();
        let h = resp.headers_mut();
        h.insert(
            "X-BSC-Request-Id",
            HeaderValue::from_str(&rid).unwrap_or(HeaderValue::from_static("req")),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(r) = self.retry_after {
            if let Ok(v) = HeaderValue::from_str(&r.to_string()) {
                h.insert(header::RETRY_AFTER, v);
            }
        }
        if self.code == "approval_pending" {
            if let Some(Value::String(id)) = self.extra.get("approval_id") {
                if let Ok(v) = HeaderValue::from_str(&format!("/v1/access-requests/{id}")) {
                    h.insert(header::LOCATION, v);
                }
            }
        }
        resp
    }
}

/// Unknown route.
pub async fn fallback() -> ApiError {
    ApiError::not_found("Route")
}
