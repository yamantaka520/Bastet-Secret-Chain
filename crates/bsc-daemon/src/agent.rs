//! Agent surface. Read-only. Every value leaves through [`release`], which
//! runs the checks in the contract's order and lets the store write the
//! ledger record before decryption.

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bsc_store::{
    access::{ApprovalStatus, TokenRecord},
    model::ItemDetail,
    Actor, StoreError,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth,
    error::ApiError,
    state::AppState,
    util::{rfc3339, value_fields},
};

type Res = Result<Response, ApiError>;

fn reason_from(
    headers: &HeaderMap,
    q: &HashMap<String, String>,
    body: Option<&str>,
) -> Result<String, ApiError> {
    let r = body
        .map(str::to_string)
        .or_else(|| q.get("reason").cloned())
        .or_else(|| {
            headers
                .get("X-BSC-Reason")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();
    if r.trim().is_empty() {
        return Err(ApiError::reason_required());
    }
    Ok(r.trim().to_string())
}

/// Item detail if the token's scope covers it; `scope_mismatch` otherwise.
/// The vault must be unsealed (scope is ciphertext at rest).
fn in_scope(v: &bsc_store::Vault, t: &TokenRecord, sref: &str) -> Result<ItemDetail, ApiError> {
    if v.is_sealed() {
        return Err(ApiError::vault_sealed());
    }
    let d = v.detail(sref).map_err(|e| match e {
        StoreError::NotFound => ApiError::not_found("Item"),
        other => other.into(),
    })?;
    let scope = t.scope.as_ref().ok_or_else(ApiError::vault_sealed)?;
    if !scope.covers(&d.path, &d.tags) {
        return Err(ApiError::scope_mismatch());
    }
    Ok(d)
}

/// Whether this read needs a human right now.
fn needs_approval(v: &bsc_store::Vault, t: &TokenRecord, d: &ItemDetail) -> Result<bool, ApiError> {
    if !d.meta.approval_required {
        return Ok(false);
    }
    if v.has_grant(&t.id, &d.meta.id)? {
        return Ok(false);
    }
    // An open task session covering the item stands in for the prompt.
    for s in v.active_sessions()? {
        if let Some(sc) = &s.scope {
            if sc.covers(&d.path, &d.tags) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// The JSON a release carries. Shared by direct reads and approved polls so
/// the two paths cannot drift.
fn value_json(
    t: &TokenRecord,
    d: &ItemDetail,
    version: u32,
    bytes: &[u8],
    now: i64,
) -> (serde_json::Value, i64) {
    let expires_in = (t.expires_at - now).max(0);
    let low = expires_in <= t.lifetime / 5 || expires_in <= 600;
    let warning = low.then(|| {
        format!(
            "token expires in {}s; call renew_access (POST /v1/token/renew) at a natural boundary",
            expires_in
        )
    });
    let (value, value_base64) = value_fields(bytes);
    (
        json!({
            "sref": d.meta.id,
            "version": version,
            "type": d.meta.item_type.as_str(),
            "name": d.name,
            "path": d.path,
            "value": value,
            "value_base64": value_base64,
            "expires_at": d.meta.expires_at.map(rfc3339),
            "warning": warning,
        }),
        expires_in,
    )
}

fn finish_value(
    body: serde_json::Value,
    expires_in: i64,
    reads_remaining: Option<u32>,
) -> Response {
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&expires_in.to_string()) {
        h.insert("X-BSC-Token-Expires-In", v);
    }
    if let Some(r) = reads_remaining {
        if let Ok(v) = HeaderValue::from_str(&r.to_string()) {
            h.insert("X-BSC-Reads-Remaining", v);
        }
    }
    resp
}

/// The one path a value takes out of the vault for an agent.
fn release(
    state: &AppState,
    headers: &HeaderMap,
    sref: &str,
    version: Option<u32>,
    reason: String,
) -> Res {
    let t = auth::agent_token(state, headers)?;
    auth::require_live(state, &t)?;
    let mut v = state.vault();
    let d = in_scope(&v, &t, sref)?;
    if needs_approval(&v, &t, &d)? {
        let actor = Actor::Token { id: t.id.clone() };
        let a = v.request_approval(&t.id, sref, &reason, state.config.approval_wait, &actor)?;
        drop(v);
        state.tick();
        return Err(ApiError::approval_pending(
            &a.id,
            a.expires_at,
            state.config.poll_interval,
        ));
    }
    let remaining = v.consume_read(&t.id).map_err(|e| match e {
        StoreError::Invalid(_) => ApiError::quota_exhausted(),
        other => other.into(),
    })?;
    let actor = Actor::Token { id: t.id.clone() };
    let bytes = v.read_version(sref, version, &actor, &reason)?;
    let n = version.unwrap_or(d.meta.current_version);
    let (body, expires_in) = value_json(&t, &d, n, &bytes, state.now());
    Ok(finish_value(body, expires_in, remaining))
}

/// `GET /v1/secrets/{sref}`
pub async fn release_current(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    let reason = reason_from(&headers, &q, None)?;
    release(&state, &headers, &sref, None, reason)
}

/// `GET /v1/secrets/{sref}/versions/{n}`
pub async fn release_version(
    State(state): State<Arc<AppState>>,
    Path((sref, n)): Path<(String, u32)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    let reason = reason_from(&headers, &q, None)?;
    release(&state, &headers, &sref, Some(n), reason)
}

/// `GET /v1/secrets` — metadata for everything in scope. Never a value.
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    let t = auth::agent_token(&state, &headers)?;
    auth::require_live(&state, &t)?;
    let v = state.vault();
    if v.is_sealed() {
        return Err(ApiError::vault_sealed());
    }
    let scope = t.scope.as_ref().ok_or_else(ApiError::vault_sealed)?;
    let path_f = q.get("path").map(|s| s.trim_end_matches('/').to_string());
    let tag_f = q.get("tag");
    let mut out = Vec::new();
    for m in v.list()? {
        let d = v.detail(&m.id)?;
        if !scope.covers(&d.path, &d.tags) {
            continue;
        }
        if let Some(p) = &path_f {
            if !(d.path == *p || d.path.starts_with(&format!("{p}/"))) {
                continue;
            }
        }
        if let Some(tg) = tag_f {
            if !d.tags.contains(tg) {
                continue;
            }
        }
        out.push(json!({
            "sref": d.meta.id,
            "name": d.name,
            "path": d.path,
            "type": d.meta.item_type.as_str(),
            "tags": d.tags,
            "env": d.meta.env,
            "expires_at": d.meta.expires_at.map(rfc3339),
            "approval_required": d.meta.approval_required,
            "version": d.meta.current_version,
        }));
    }
    Ok(Json(json!({ "items": out })).into_response())
}

#[derive(Deserialize)]
pub struct AccessRequest {
    sref: String,
    #[serde(default)]
    reason: String,
}

/// `POST /v1/access-requests` — ask explicitly.
pub async fn request_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Json<AccessRequest>, JsonRejection>,
) -> Res {
    let Json(req) = body.map_err(|e| ApiError::invalid_request(e.body_text()))?;
    let reason = reason_from(&headers, &HashMap::new(), Some(&req.reason))?;
    let t = auth::agent_token(&state, &headers)?;
    auth::require_live(&state, &t)?;
    let mut v = state.vault();
    let d = in_scope(&v, &t, &req.sref)?;
    if !needs_approval(&v, &t, &d)? {
        return Ok(Json(json!({ "status": "not_required", "sref": req.sref })).into_response());
    }
    let actor = Actor::Token { id: t.id.clone() };
    let a = v.request_approval(
        &t.id,
        &req.sref,
        &reason,
        state.config.approval_wait,
        &actor,
    )?;
    drop(v);
    state.tick();
    Err(ApiError::approval_pending(
        &a.id,
        a.expires_at,
        state.config.poll_interval,
    ))
}

/// `GET /v1/access-requests/{apr}` — poll. Hands the value over once on approval.
pub async fn check_access(
    State(state): State<Arc<AppState>>,
    Path(apr): Path<String>,
    headers: HeaderMap,
) -> Res {
    let t = auth::agent_token(&state, &headers)?;
    auth::require_live(&state, &t)?;
    state.tick();
    let mut v = state.vault();
    let a = v
        .approval(&apr)
        .map_err(|_| ApiError::not_found("Approval"))?;
    if a.token_id != t.id {
        return Err(ApiError::not_found("Approval"));
    }
    match a.status {
        ApprovalStatus::Pending => Ok((
            StatusCode::OK,
            [(header::RETRY_AFTER, state.config.poll_interval.to_string())],
            Json(json!({
                "status": "pending",
                "approval_id": a.id,
                "expires_at": rfc3339(a.expires_at),
                "retry_after": state.config.poll_interval,
            })),
        )
            .into_response()),
        ApprovalStatus::Denied => Err(ApiError::approval_denied()),
        ApprovalStatus::Timeout => Err(ApiError::approval_timeout()),
        ApprovalStatus::Approved => {
            if !v.consume_approval(&a.id)? {
                return Ok(Json(json!({
                    "status": "consumed",
                    "approval_id": a.id,
                    "next_action": "The value was already delivered through this approval. Call get_secret again; the grant lets it through without another prompt.",
                }))
                .into_response());
            }
            let d = in_scope(&v, &t, &a.item_id)?;
            let remaining = v.consume_read(&t.id).map_err(|e| match e {
                StoreError::Invalid(_) => ApiError::quota_exhausted(),
                other => other.into(),
            })?;
            let actor = Actor::Token { id: t.id.clone() };
            let bytes = v.read(&a.item_id, &actor, &a.reason)?;
            // Same value body as a direct release, plus the approval status.
            let (mut body, expires_in) =
                value_json(&t, &d, d.meta.current_version, &bytes, state.now());
            if let Some(m) = body.as_object_mut() {
                m.insert("status".into(), json!("approved"));
                m.insert("approval_id".into(), json!(a.id));
            }
            Ok(finish_value(body, expires_in, remaining))
        }
    }
}

/// `POST /v1/token/renew`
pub async fn renew(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    let t = auth::agent_token(&state, &headers)?;
    if t.revoked_at.is_some() {
        return Err(ApiError::token_revoked());
    }
    let now = state.now();
    if !t.is_renewable(now) {
        if !t.is_live(now) {
            return Err(ApiError::token_expired(t.expires_at, false));
        }
        return Err(ApiError::invalid_request(format!(
            "not yet in the renewal window; renewal opens at {}",
            rfc3339(t.expires_at - t.lifetime / 4)
        )));
    }
    let mut v = state.vault();
    let actor = Actor::Token { id: t.id.clone() };
    let r = v.renew_token(&t.id, &actor)?;
    Ok(Json(json!({
        "expires_at": rfc3339(r.expires_at),
        "renewable_until": rfc3339(r.expires_at + TokenRecord::RENEWAL_GRACE),
        "max_lifetime_until": rfc3339(r.max_lifetime_until),
    }))
    .into_response())
}

/// `GET /v1/token` — inspect the calling token. Never its value.
pub async fn whoami(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    let t = auth::agent_token(&state, &headers)?;
    let now = state.now();
    Ok(Json(json!({
        "id": t.id,
        "label": t.label,
        "scope": t.scope,
        "expires_at": rfc3339(t.expires_at),
        "expires_in": (t.expires_at - now).max(0),
        "renewable_now": t.is_renewable(now),
        "renewable_until": rfc3339(t.expires_at + TokenRecord::RENEWAL_GRACE),
        "reads_remaining": t.reads_remaining(),
        "rate_limit_per_min": t.rate_limit_per_min,
        "revoked": t.revoked_at.is_some(),
        "live": t.is_live(now),
    }))
    .into_response())
}
