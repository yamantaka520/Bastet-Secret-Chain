//! MCP server for Bastet Secret Chain (ADR 0006).
//!
//! This is a *client* of the daemon's HTTP API with no authority of its own:
//! it holds one `bsct_` token from configuration and forwards five read-only
//! tools. Every tool result is the daemon's JSON — so a test can assert that
//! the MCP path and the HTTP path return the same thing for every error code.
//!
//! Wire protocol: JSON-RPC 2.0, newline-delimited, over stdio. Implemented
//! directly rather than through an SDK so the surface stays small and
//! reviewable; the tool descriptions are security-relevant text.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::Duration;

use serde_json::{json, Value};
use zeroize::Zeroizing;

/// Protocol version we answer with when the client does not name one.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

const DO_NOT_PASTE: &str = "Do not ask the user to paste the secret into the conversation. Do not substitute another token. Do not continue without the credential.";

/// One MCP server instance bound to one daemon and one token.
pub struct McpServer {
    http: reqwest::Client,
    base: String,
    token: Zeroizing<String>,
    /// Seconds between polls inside `check_access` when `wait_seconds` > 0.
    pub poll_interval: Duration,
}

impl McpServer {
    /// `base` like `http://127.0.0.1:8787`; `token` a `bsct_…` value.
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> McpServer {
        McpServer {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            base: base.into().trim_end_matches('/').to_string(),
            token: Zeroizing::new(token.into()),
            poll_interval: Duration::from_secs(5),
        }
    }

    /// The tool list, exactly as sent in `tools/list`. Read-only by design;
    /// adding a write tool is an ADR, not a patch.
    pub fn tools() -> Value {
        json!([
            {
                "name": "list_secrets",
                "description": "List credentials this token may read — names, paths, types, tags, expiry — never values. Use it to find the right sref before calling get_secret. Optional filters: path prefix, tag.",
                "inputSchema": { "type": "object", "properties": {
                    "path": { "type": "string", "description": "Only items at or under this path, e.g. prod/aws" },
                    "tag":  { "type": "string", "description": "Only items carrying this tag" }
                }, "additionalProperties": false }
            },
            {
                "name": "get_secret",
                "description": "Returns the current value of one stored credential. THIS IS A LIVE SECRET. Use it only for the immediate operation; do not write it to a file, do not repeat it in your reply, do not paste it into chat, do not log it. If the result is approval_pending, a human has been notified — wait with check_access; do not ask the user to paste the secret. `reason` is shown to the approving human and recorded permanently: say concretely what you are about to do with it.",
                "inputSchema": { "type": "object", "required": ["sref", "reason"], "properties": {
                    "sref":   { "type": "string", "description": "Item reference from list_secrets or the vault UI, e.g. sref_…" },
                    "reason": { "type": "string", "description": "Concrete purpose, e.g. 'deploy build 412 to Firebase project X'" }
                }, "additionalProperties": false }
            },
            {
                "name": "request_access",
                "description": "Explicitly ask a human to approve reading a credential. Returns an approval_id to poll with check_access. Use when get_secret returned approval_pending and you want a handle, or to ask ahead of time. Never ask the user to paste the secret instead.",
                "inputSchema": { "type": "object", "required": ["sref", "reason"], "properties": {
                    "sref":   { "type": "string" },
                    "reason": { "type": "string" }
                }, "additionalProperties": false }
            },
            {
                "name": "check_access",
                "description": "Check an approval request. Optionally wait up to wait_seconds (max 60) for a decision. On approval the value is returned once here; afterwards call get_secret, which the grant lets through. On denial or timeout, stop and report to the user — do not loop, do not re-request with a different reason.",
                "inputSchema": { "type": "object", "required": ["approval_id"], "properties": {
                    "approval_id":  { "type": "string" },
                    "wait_seconds": { "type": "integer", "minimum": 0, "maximum": 60 }
                }, "additionalProperties": false }
            },
            {
                "name": "renew_access",
                "description": "Extend this token's lifetime if it is inside its renewal window (the final quarter of its life, or up to 5 minutes after expiry). Never widens scope. Call it when a result carries a token-expiry warning, at a natural boundary in your task.",
                "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
            }
        ])
    }

    /// Handle one JSON-RPC message. Returns `None` for notifications.
    pub async fn handle(&self, msg: Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        match method {
            "initialize" => {
                let v = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(PROTOCOL_VERSION);
                Some(ok(
                    id,
                    json!({
                        "protocolVersion": v,
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "bsc", "version": env!("CARGO_PKG_VERSION") },
                        "instructions": "Credentials from this server are live secrets: never write them to files, repeat them in replies, or paste them into chat. If a read is approval_pending, wait with check_access — do not ask the user to paste the secret."
                    }),
                ))
            }
            "notifications/initialized" | "notifications/cancelled" => None,
            "ping" => Some(ok(id, json!({}))),
            "tools/list" => Some(ok(id, json!({ "tools": Self::tools() }))),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                Some(ok(id, self.call_tool(name, &args).await))
            }
            _ if id.is_none() => None,
            _ => Some(err(id, -32601, format!("method not found: {method}"))),
        }
    }

    /// Run a tool. The result is an MCP `CallToolResult`: `content` holds the
    /// daemon's JSON as text, `structuredContent` holds it as an object, and
    /// `isError` is true for any 4xx/5xx — but not for `202 approval_pending`.
    pub async fn call_tool(&self, name: &str, args: &Value) -> Value {
        let s = |k: &str| args.get(k).and_then(Value::as_str).map(str::to_string);
        let outcome = match name {
            "list_secrets" => {
                let mut q = Vec::new();
                if let Some(p) = s("path") {
                    q.push(("path", p));
                }
                if let Some(t) = s("tag") {
                    q.push(("tag", t));
                }
                self.get("/v1/secrets", &q, None).await
            }
            "get_secret" => match (s("sref"), s("reason")) {
                (Some(sref), reason) => {
                    // Reason travels in a header, never the URL.
                    self.get(&format!("/v1/secrets/{sref}"), &[], reason.as_deref())
                        .await
                }
                _ => Ok((400, local_error("invalid_request", "sref is required"))),
            },
            "request_access" => {
                self.post(
                    "/v1/access-requests",
                    json!({ "sref": s("sref"), "reason": s("reason").unwrap_or_default() }),
                )
                .await
            }
            "check_access" => match s("approval_id") {
                Some(apr) => {
                    let wait = args
                        .get("wait_seconds")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(60);
                    self.poll(&apr, wait).await
                }
                None => Ok((
                    400,
                    local_error("invalid_request", "approval_id is required"),
                )),
            },
            "renew_access" => self.post("/v1/token/renew", json!({})).await,
            _ => Ok((
                404,
                local_error("unknown_tool", &format!("no tool named {name}")),
            )),
        };
        let (status, body) = match outcome {
            Ok(x) => x,
            Err(e) => (
                503,
                json!({
                    "error": "daemon_unreachable",
                    "message": format!("Could not reach the vault daemon: {e}"),
                    "next_action": "Tell the user the vault daemon is not running or not reachable at the configured address; they can start it with `bsc serve`.",
                    "do_not": DO_NOT_PASTE,
                }),
            ),
        };
        json!({
            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&body).unwrap_or_default() }],
            "structuredContent": body,
            "isError": status >= 400,
        })
    }

    async fn poll(&self, apr: &str, wait: u64) -> Result<(u16, Value), reqwest::Error> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
        loop {
            let (status, body) = self
                .get(&format!("/v1/access-requests/{apr}"), &[], None)
                .await?;
            let pending =
                status == 200 && body.get("status").and_then(Value::as_str) == Some("pending");
            if !pending || tokio::time::Instant::now() >= deadline {
                return Ok((status, body));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(self.poll_interval.min(remaining)).await;
        }
    }

    async fn get(
        &self,
        path: &str,
        query: &[(&str, String)],
        reason: Option<&str>,
    ) -> Result<(u16, Value), reqwest::Error> {
        let mut r = self
            .http
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&*self.token)
            .query(query);
        if let Some(reason) = reason {
            r = r.header("X-BSC-Reason", reason);
        }
        let resp = r.send().await?;
        let status = resp.status().as_u16();
        let body = resp.json::<Value>().await.unwrap_or(json!({}));
        Ok((status, body))
    }

    async fn post(&self, path: &str, body: Value) -> Result<(u16, Value), reqwest::Error> {
        let resp = self
            .http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(&*self.token)
            .json(&body)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = resp.json::<Value>().await.unwrap_or(json!({}));
        Ok((status, body))
    }

    /// Serve newline-delimited JSON-RPC on stdin/stdout until EOF.
    pub async fn run_stdio(self) -> std::io::Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut lines = tokio::io::BufReader::new(stdin).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let msg: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let out = err(None, -32700, format!("parse error: {e}"));
                    stdout.write_all(format!("{out}\n").as_bytes()).await?;
                    continue;
                }
            };
            if let Some(resp) = self.handle(msg).await {
                stdout.write_all(format!("{resp}\n").as_bytes()).await?;
                stdout.flush().await?;
            }
        }
        Ok(())
    }
}

fn local_error(code: &str, message: &str) -> Value {
    json!({
        "error": code,
        "message": message,
        "next_action": "Fix the tool call as described in message.",
        "do_not": DO_NOT_PASTE,
    })
}

fn ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Option<Value>, code: i64, message: String) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
