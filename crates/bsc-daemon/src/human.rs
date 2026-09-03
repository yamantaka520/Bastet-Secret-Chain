//! Human surface. Session cookie, loopback, same-origin. This is the only
//! place items are written and tokens are minted.

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bsc_store::{
    access::{ApprovalRecord, NewToken, Scope, SessionRecord, TokenRecord},
    audit::ChainStatus,
    model::{ItemMeta, ItemType, NewItem},
    Actor,
};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{
    auth,
    error::ApiError,
    state::AppState,
    util::{decode_value, rfc3339, value_fields},
};

type Res = Result<Response, ApiError>;

fn body<T: serde::de::DeserializeOwned>(b: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    b.map(|Json(v)| v)
        .map_err(|e| ApiError::invalid_request(e.body_text()))
}

fn meta_json(m: &ItemMeta) -> serde_json::Value {
    json!({
        "sref": m.id,
        "type": m.item_type.as_str(),
        "env": m.env,
        "created": rfc3339(m.created),
        "updated": rfc3339(m.updated),
        "expires_at": m.expires_at.map(rfc3339),
        "approval_required": m.approval_required,
        "local_approval_only": m.local_approval_only,
        "has_use_binding": m.has_use_binding,
        "rotation_days": m.rotation_days,
        "rotation_due_at": m.rotation_due_at().map(rfc3339),
        "version": m.current_version,
        "size": m.size,
    })
}

fn token_json(t: &TokenRecord, now: i64) -> serde_json::Value {
    json!({
        "id": t.id,
        "label": t.label,
        "scope": t.scope,
        "created": rfc3339(t.created),
        "expires_at": rfc3339(t.expires_at),
        "max_lifetime_until": rfc3339(t.max_lifetime_until),
        "max_reads": t.max_reads,
        "reads_used": t.reads_used,
        "rate_limit_per_min": t.rate_limit_per_min,
        "created_by": t.created_by,
        "revoked_at": t.revoked_at.map(rfc3339),
        "live": t.is_live(now),
    })
}

fn session_json(s: &SessionRecord, now: i64) -> serde_json::Value {
    json!({
        "id": s.id,
        "scope": s.scope,
        "opened": rfc3339(s.opened),
        "expires_at": rfc3339(s.expires_at),
        "closed_at": s.closed_at.map(rfc3339),
        "active": s.is_active(now),
        "seconds_left": (s.expires_at - now).max(0),
    })
}

fn approval_json(a: &ApprovalRecord, now: i64) -> serde_json::Value {
    json!({
        "id": a.id,
        "token_id": a.token_id,
        "sref": a.item_id,
        "reason": a.reason,
        "requested_at": rfc3339(a.requested_at),
        "expires_at": rfc3339(a.expires_at),
        "seconds_left": (a.expires_at - now).max(0),
        "status": a.status.as_str(),
        "decided_at": a.decided_at.map(rfc3339),
        "decided_by": a.decided_by,
        "escalation": a.escalation,
    })
}

// ------------------------------------------------------------------ vault

#[derive(Deserialize)]
pub struct Unseal {
    passphrase: String,
}

/// `POST /v1/vault/unseal` — doubles as login. Argon2id runs on a blocking
/// thread so a 64 MiB derivation does not stall the runtime.
pub async fn unseal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    b: Result<Json<Unseal>, JsonRejection>,
) -> Res {
    auth::same_origin(&state, &headers, true)?;
    let client = auth::client_addr(&state, &headers);
    if !state.login_allowed(&client) {
        return Err(ApiError::rate_limited(600));
    }
    let Unseal { passphrase } = body(b)?;
    let pw = Zeroizing::new(passphrase);
    let st = state.clone();
    let outcome = tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
        let mut v = st.vault();
        // No session exists yet, so the actor is the system.
        if v.is_sealed() {
            v.unseal(pw.as_bytes(), &Actor::System)?;
        } else if !v.verify_passphrase(pw.as_bytes(), &Actor::System)? {
            return Err(ApiError::bad_passphrase());
        }
        Ok(())
    })
    .await
    .map_err(ApiError::internal)?;
    if let Err(e) = outcome {
        if e.code == "bad_passphrase" {
            state.login_failed(&client);
        }
        return Err(e);
    }
    let id = state.open_human_session();
    let mut resp = (
        StatusCode::OK,
        Json(json!({ "sealed": false, "session": id })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, auth::set_cookie(&state, &id));
    Ok(resp)
}

#[derive(Deserialize)]
pub struct ChangePassphrase {
    current: String,
    new: String,
}

/// `POST /v1/vault/passphrase` — rotate the passphrase. Re-authenticates with
/// the current one; Argon2id runs twice, so this goes to a blocking thread.
pub async fn change_passphrase(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    b: Result<Json<ChangePassphrase>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = body(b)?;
    if req.new.chars().count() < 12 {
        return Err(ApiError::invalid_request(
            "new passphrase must be at least 12 characters",
        ));
    }
    let cur = Zeroizing::new(req.current);
    let new = Zeroizing::new(req.new);
    let st = state.clone();
    tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
        let mut v = st.vault();
        v.rotate_passphrase(cur.as_bytes(), new.as_bytes(), &actor)?;
        Ok(())
    })
    .await
    .map_err(ApiError::internal)??;
    // Every other session must re-authenticate against the new passphrase.
    state.clear_human_sessions();
    Ok(Json(json!({ "rotated": true, "note": "all human sessions were ended; log in again with the new passphrase" })).into_response())
}

#[derive(Deserialize, Default)]
pub struct DeleteItem {
    #[serde(default)]
    reason: String,
}

/// `DELETE /v1/items/{sref}` — hard delete; the ledger keeps the history.
pub async fn delete_item(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    headers: HeaderMap,
    b: Result<Json<DeleteItem>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = match b {
        Ok(Json(r)) => r,
        Err(_) => DeleteItem::default(),
    };
    state.vault().delete_item(&sref, &actor, &req.reason)?;
    Ok(Json(json!({ "sref": sref, "deleted": true })).into_response())
}

#[derive(Deserialize)]
pub struct Grant {
    token_id: String,
    sref: String,
    ttl_seconds: Option<i64>,
}

/// `POST /v1/grants` — pre-authorize a token for an item (ADR 0005 §1).
pub async fn create_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    b: Result<Json<Grant>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = body(b)?;
    let ttl = req.ttl_seconds.unwrap_or(state.config.grant_ttl);
    let until = state
        .vault()
        .grant_direct(&req.token_id, &req.sref, ttl, &actor)
        .map_err(|e| match e {
            bsc_store::StoreError::NotFound => ApiError::not_found("Token or item"),
            o => o.into(),
        })?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token_id": req.token_id, "sref": req.sref, "until": rfc3339(until) })),
    )
        .into_response())
}

/// `GET /v1/grants` — live grants with labels where the vault is unsealed.
pub async fn list_grants(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    auth::human(&state, &headers, false)?;
    let v = state.vault();
    let mut out = Vec::new();
    for g in v.active_grants()? {
        let (tok, item, apr, until) = (g.token_id, g.item_id, g.approval_id, g.expires_at);
        let label = v.token(&tok).ok().and_then(|t| t.label);
        let name = v.detail(&item).ok().map(|d| d.name);
        out.push(json!({ "token_id": tok, "token_label": label, "sref": item, "item_name": name, "source": if apr == "pre" { "pre-authorized" } else { "approval" }, "approval_id": if apr == "pre" { Value::Null } else { json!(apr) }, "until": rfc3339(until) }));
    }
    Ok(Json(json!({ "grants": out })).into_response())
}

/// `DELETE /v1/grants/{tok}/{sref}`
pub async fn revoke_grant(
    State(state): State<Arc<AppState>>,
    Path((tok, sref)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let removed = state.vault().revoke_grant(&tok, &sref, &actor)?;
    if !removed {
        return Err(ApiError::not_found("Grant"));
    }
    Ok(Json(json!({ "token_id": tok, "sref": sref, "revoked": true })).into_response())
}

/// `POST /v1/vault/seal`
pub async fn seal(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    state.vault().seal(&actor)?;
    state.clear_human_sessions();
    Ok(Json(json!({ "sealed": true })).into_response())
}

/// `GET /v1/vault/status` — minimal without a session, fuller with one.
pub async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    let v = state.vault();
    let mut out = json!({
        "sealed": v.is_sealed(),
        "version": crate::VERSION,
        "build": { "sha": crate::BUILD_SHA, "date": crate::BUILD_DATE },
        "uptime": state.uptime(),
        "public_origin": state.config.public_origin,
        "unattended_unseal": state.config.unattended_unseal,
    });
    if auth::human(&state, &headers, false).is_ok() {
        let chain = match v.audit_verify()? {
            ChainStatus::Intact { len, head } => {
                json!({ "intact": true, "len": len, "head": hex::encode(head) })
            }
            ChainStatus::Broken { at } => json!({ "intact": false, "broken_at": at }),
        };
        let now = state.now();
        out["items"] = json!(v.list()?.len());
        out["pending_approvals"] = json!(v.pending_approvals()?.len());
        out["active_sessions"] = json!(v.active_sessions()?.len());
        out["live_tokens"] = json!(v.list_tokens()?.iter().filter(|t| t.is_live(now)).count());
        out["chain"] = chain;
        out["kdf"] = json!({ "m_cost_kib": v.kdf_params().m_cost_kib, "t_cost": v.kdf_params().t_cost, "p_cost": v.kdf_params().p_cost });
    }
    Ok(Json(out).into_response())
}

// ------------------------------------------------------------------ items

/// `GET /v1/items`
pub async fn list_items(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    auth::human(&state, &headers, false)?;
    let v = state.vault();
    let mut out = Vec::new();
    for m in v.list()? {
        let mut j = meta_json(&m);
        if !v.is_sealed() {
            let d = v.detail(&m.id)?;
            j["name"] = json!(d.name);
            j["path"] = json!(d.path);
            j["tags"] = json!(d.tags);
            j["use_binding"] = json!(d.use_binding);
        }
        out.push(j);
    }
    Ok(Json(json!({ "items": out, "sealed": v.is_sealed() })).into_response())
}

#[derive(Deserialize)]
pub struct CreateItem {
    path: String,
    name: String,
    #[serde(rename = "type")]
    item_type: String,
    #[serde(default)]
    tags: Vec<String>,
    env: Option<String>,
    approval_required: Option<bool>,
    expires_at: Option<i64>,
    rotation_days: Option<u32>,
    value: Option<String>,
    value_base64: Option<String>,
}

/// `POST /v1/items`
pub async fn create_item(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    b: Result<Json<CreateItem>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = body(b)?;
    let item_type =
        ItemType::parse(&req.item_type).map_err(|_| ApiError::invalid_request("unknown type"))?;
    let bytes = Zeroizing::new(
        decode_value(req.value.as_deref(), req.value_base64.as_deref())
            .map_err(ApiError::invalid_request)?,
    );
    let mut v = state.vault();
    let id = v.put(
        NewItem {
            path: req.path,
            name: req.name,
            item_type,
            tags: req.tags,
            env: req.env,
            approval_required: req.approval_required,
            expires_at: req.expires_at,
            rotation_days: req.rotation_days,
        },
        &bytes,
        &actor,
        "created in UI",
    )?;
    let d = v.detail(&id)?;
    let mut j = meta_json(&d.meta);
    j["name"] = json!(d.name);
    j["path"] = json!(d.path);
    j["tags"] = json!(d.tags);
    Ok((StatusCode::CREATED, Json(j)).into_response())
}

/// `GET /v1/items/{sref}`
pub async fn item_detail(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    headers: HeaderMap,
) -> Res {
    auth::human(&state, &headers, false)?;
    let v = state.vault();
    let m = v.meta(&sref)?;
    let mut j = meta_json(&m);
    if !v.is_sealed() {
        let d = v.detail(&sref)?;
        j["name"] = json!(d.name);
        j["path"] = json!(d.path);
        j["tags"] = json!(d.tags);
        j["use_binding"] = json!(d.use_binding);
    }
    Ok(Json(j).into_response())
}

#[derive(Deserialize)]
pub struct PatchItem {
    approval_required: Option<bool>,
    local_approval_only: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    expires_at: Option<Option<i64>>,
    #[serde(default, deserialize_with = "double_option")]
    env: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    rotation_days: Option<Option<u32>>,
}

fn double_option<'de, T, D>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// `PATCH /v1/items/{sref}`
pub async fn patch_item(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    headers: HeaderMap,
    b: Result<Json<PatchItem>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let p = body(b)?;
    let m = state.vault().set_item_flags(
        &sref,
        p.approval_required,
        p.local_approval_only,
        p.expires_at,
        p.env,
        p.rotation_days,
        &actor,
    )?;
    Ok(Json(meta_json(&m)).into_response())
}

#[derive(Deserialize)]
pub struct AddVersion {
    value: Option<String>,
    value_base64: Option<String>,
    note: Option<String>,
}

/// `POST /v1/items/{sref}/versions`
pub async fn add_version(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    headers: HeaderMap,
    b: Result<Json<AddVersion>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = body(b)?;
    let bytes = Zeroizing::new(
        decode_value(req.value.as_deref(), req.value_base64.as_deref())
            .map_err(ApiError::invalid_request)?,
    );
    let mut v = state.vault();
    let n = v.add_version(&sref, &bytes, req.note.as_deref(), &actor, "rotated in UI")?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "sref": sref, "version": n })),
    )
        .into_response())
}

#[derive(Deserialize, Default)]
pub struct Reveal {
    passphrase: Option<String>,
}

/// `POST /v1/items/{sref}/reveal` — the human read. Approval-required items
/// demand the passphrase again.
pub async fn reveal(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    headers: HeaderMap,
    b: Result<Json<Reveal>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = match b {
        Ok(Json(r)) => r,
        Err(e) if e.body_text().contains("Expected request with") => Reveal::default(),
        Err(e) => return Err(ApiError::invalid_request(e.body_text())),
    };
    let st = state.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<(String, Vec<u8>, u32), ApiError> {
        let mut v = st.vault();
        let m = v.meta(&sref)?;
        if m.approval_required {
            let pw = Zeroizing::new(req.passphrase.ok_or_else(|| {
                ApiError::invalid_request("passphrase required to reveal an approval-required item")
            })?);
            if !v.verify_passphrase(pw.as_bytes(), &actor)? {
                return Err(ApiError::bad_passphrase());
            }
        }
        let bytes = v.read(&sref, &actor, "revealed in UI")?;
        Ok((sref, bytes.to_vec(), m.current_version))
    })
    .await
    .map_err(ApiError::internal)??;
    let (sref, bytes, version) = out;
    let (value, value_base64) = value_fields(&bytes);
    let mut resp = Json(
        json!({ "sref": sref, "version": version, "value": value, "value_base64": value_base64 }),
    )
    .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

// ----------------------------------------------------------------- tokens

/// `GET /v1/tokens`
pub async fn list_tokens(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    auth::human(&state, &headers, false)?;
    let v = state.vault();
    let now = state.now();
    let out: Vec<_> = v
        .list_tokens()?
        .iter()
        .map(|t| token_json(t, now))
        .collect();
    Ok(Json(json!({ "tokens": out })).into_response())
}

#[derive(Deserialize)]
pub struct Mint {
    label: String,
    scope: Scope,
    lifetime: Option<i64>,
    max_lifetime: Option<i64>,
    max_reads: Option<u32>,
    rate_limit_per_min: Option<u32>,
}

/// `POST /v1/tokens` — the value appears in this response and nowhere else.
pub async fn mint_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    b: Result<Json<Mint>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = body(b)?;
    let c = &state.config;
    let mut v = state.vault();
    let m = v.mint_token(
        NewToken {
            label: req.label,
            scope: req.scope,
            lifetime: req.lifetime.unwrap_or(c.default_token_lifetime),
            max_lifetime: req.max_lifetime.unwrap_or(c.default_max_lifetime),
            max_reads: req.max_reads,
            rate_limit_per_min: req.rate_limit_per_min.unwrap_or(c.default_rate_limit),
        },
        &actor,
    )?;
    let mut j = token_json(&m.record, state.now());
    j["value"] = json!(*m.value);
    j["shown_once"] = json!(true);
    let mut resp = (StatusCode::CREATED, Json(j)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// `DELETE /v1/tokens/{tok}`
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Path(tok): Path<String>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let mut v = state.vault();
    let t = v.revoke_token(&tok, &actor).map_err(|e| match e {
        bsc_store::StoreError::NotFound => ApiError::not_found("Token"),
        o => o.into(),
    })?;
    Ok(Json(token_json(&t, state.now())).into_response())
}

// --------------------------------------------------------------- sessions

/// `GET /v1/sessions`
pub async fn list_sessions(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    auth::human(&state, &headers, false)?;
    let v = state.vault();
    let now = state.now();
    let out: Vec<_> = v
        .active_sessions()?
        .iter()
        .map(|s| session_json(s, now))
        .collect();
    Ok(Json(json!({ "sessions": out })).into_response())
}

#[derive(Deserialize)]
pub struct OpenSession {
    scope: Scope,
    duration_seconds: Option<i64>,
}

/// `POST /v1/sessions`
pub async fn open_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    b: Result<Json<OpenSession>, JsonRejection>,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let req = body(b)?;
    let mut v = state.vault();
    let s = v.open_session(
        req.scope,
        req.duration_seconds
            .unwrap_or(state.config.default_session_duration),
        &actor,
    )?;
    Ok((StatusCode::CREATED, Json(session_json(&s, state.now()))).into_response())
}

/// `DELETE /v1/sessions/{ses}`
pub async fn close_session(
    State(state): State<Arc<AppState>>,
    Path(ses): Path<String>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::human(&state, &headers, true)?;
    let mut v = state.vault();
    let s = v.close_session(&ses, &actor).map_err(|e| match e {
        bsc_store::StoreError::NotFound => ApiError::not_found("Session"),
        o => o.into(),
    })?;
    Ok(Json(session_json(&s, state.now())).into_response())
}

// -------------------------------------------------------------- approvals

/// `GET /v1/approvals` — the inbox.
pub async fn list_approvals(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    auth::human(&state, &headers, false)?;
    state.tick();
    let v = state.vault();
    let now = state.now();
    let mut out = Vec::new();
    for a in v.pending_approvals()? {
        let mut j = approval_json(&a, now);
        if let Ok(t) = v.token(&a.token_id) {
            j["token_label"] = json!(t.label);
        }
        if let Ok(d) = v.detail(&a.item_id) {
            j["item_name"] = json!(d.name);
            j["item_path"] = json!(d.path);
            j["item_type"] = json!(d.meta.item_type.as_str());
        }
        out.push(j);
    }
    Ok(Json(json!({ "approvals": out })).into_response())
}

fn decide(state: &AppState, headers: &HeaderMap, apr: &str, approve: bool) -> Res {
    let actor = auth::human(state, headers, true)?;
    state.tick();
    let mut v = state.vault();
    let a = v
        .decide_approval(apr, approve, state.config.grant_ttl, &actor)
        .map_err(|e| match e {
            bsc_store::StoreError::NotFound => ApiError::not_found("Approval"),
            o => o.into(),
        })?;
    Ok(Json(approval_json(&a, state.now())).into_response())
}

/// `POST /v1/approvals/{apr}/approve`
pub async fn approve(
    State(state): State<Arc<AppState>>,
    Path(apr): Path<String>,
    headers: HeaderMap,
) -> Res {
    decide(&state, &headers, &apr, true)
}

/// `POST /v1/approvals/{apr}/deny`
pub async fn deny(
    State(state): State<Arc<AppState>>,
    Path(apr): Path<String>,
    headers: HeaderMap,
) -> Res {
    decide(&state, &headers, &apr, false)
}

// ------------------------------------------------------------------ audit

/// `GET /v1/audit?from=&limit=`
pub async fn audit_read(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    auth::human(&state, &headers, false)?;
    let from: u64 = q.get("from").and_then(|s| s.parse().ok()).unwrap_or(1);
    let limit: u64 = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let subject = q.get("subject").cloned();
    let v = state.vault();
    let recs: Vec<_> = match &subject {
        Some(s) => v.audit_read_subject(s, from, limit)?,
        None => v.audit_read(from, limit)?,
    }
    .into_iter()
    .map(|r| {
        json!({
            "n": r.n,
            "ts": rfc3339(r.ts),
            "actor": r.actor,
            "action": r.action,
            "subject": r.subject,
            "outcome": r.outcome,
            "meta": serde_json::from_str::<serde_json::Value>(&r.meta).unwrap_or(json!(r.meta)),
            "hash": hex::encode(r.hash),
        })
    })
    .collect();
    Ok(Json(json!({ "records": recs, "from": from, "limit": limit })).into_response())
}

/// `GET /v1/audit/verify`
pub async fn audit_verify(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    auth::human(&state, &headers, false)?;
    let v = state.vault();
    Ok(Json(match v.audit_verify()? {
        ChainStatus::Intact { len, head } => {
            json!({ "intact": true, "len": len, "head": hex::encode(head) })
        }
        ChainStatus::Broken { at } => json!({ "intact": false, "broken_at": at }),
    })
    .into_response())
}

/// `POST /v1/handoff-links` — off in M2.
pub async fn handoff_disabled(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Res {
    auth::human(&state, &headers, true)?;
    if !state.config.handoff_enabled {
        return Err(ApiError::handoff_disabled());
    }
    Err(ApiError::invalid_request(
        "handoff links are not implemented",
    ))
}
