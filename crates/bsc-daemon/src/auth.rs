//! Who is calling. Plain functions rather than extractors so the ordering of
//! checks is explicit at each call site.

use axum::http::{header, HeaderMap, HeaderValue};
use bsc_store::{access::TokenRecord, Actor};

use crate::{error::ApiError, state::AppState};

/// Cookie name for the human session.
pub const COOKIE: &str = "bsc_session";
/// Header a browser client must send on state-changing human calls. Its
/// presence forces a CORS preflight, which a foreign origin cannot pass.
pub const CLIENT_HEADER: &str = "X-BSC-Client";

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| t.starts_with("bsct_"))
}

/// Resolve the bearer token to its record. Does **not** check liveness so
/// that renewal can accept an expired token; call [`require_live`] next.
pub fn agent_token(state: &AppState, headers: &HeaderMap) -> Result<TokenRecord, ApiError> {
    let value = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    let v = state.vault();
    v.token_by_value(value)?.ok_or_else(ApiError::unauthorized)
}

/// Revoked, expired (renewable or not), then rate limit.
pub fn require_live(state: &AppState, t: &TokenRecord) -> Result<(), ApiError> {
    if t.revoked_at.is_some() {
        return Err(ApiError::token_revoked());
    }
    let now = state.now();
    if !t.is_live(now) {
        return Err(ApiError::token_expired(t.expires_at, t.is_renewable(now)));
    }
    state
        .rate_check(&t.id, t.rate_limit_per_min)
        .map_err(ApiError::rate_limited)
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    for c in headers.get_all(header::COOKIE) {
        let s = c.to_str().ok()?;
        for part in s.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix(&format!("{COOKIE}=")) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Same-origin discipline for the human surface: refuse foreign `Origin`s and
/// require the client header on anything that changes state.
pub fn same_origin(headers: &HeaderMap, mutating: bool) -> Result<(), ApiError> {
    if let Some(o) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let ok =
            o.starts_with("http://127.0.0.1:") || o.starts_with("http://localhost:") || o == "null";
        if !ok {
            return Err(ApiError::forbidden_origin());
        }
    }
    if mutating && !headers.contains_key(CLIENT_HEADER) {
        return Err(ApiError::forbidden_origin());
    }
    Ok(())
}

/// Human session from the cookie, touched.
pub fn human(state: &AppState, headers: &HeaderMap, mutating: bool) -> Result<Actor, ApiError> {
    same_origin(headers, mutating)?;
    let id = cookie_value(headers).ok_or_else(ApiError::unauthorized)?;
    state
        .touch_human_session(&id)
        .ok_or_else(ApiError::unauthorized)
}

/// `Set-Cookie` for a new human session.
pub fn set_cookie(id: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict"))
        .unwrap_or(HeaderValue::from_static(""))
}
