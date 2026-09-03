//! `use_secret`: the daemon makes an outbound HTTPS request on the agent's
//! behalf with the credential injected, so the value never reaches the agent.
//!
//! Policy is the same as a read — token, scope, approval, quota — and then two
//! more gates that only a human can widen: the item's **use binding** (URL
//! patterns, header template, methods) and the SSRF guard (https only, no
//! redirects, no private or loopback targets unless configured, body cap,
//! timeout). The ledger records `secret_used` with the target host and path,
//! never the value and never the response.

use std::{net::IpAddr, sync::Arc, time::Duration};

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bsc_store::{model::ItemDetail, Actor, StoreError};
use serde::Deserialize;
use serde_json::json;

use crate::{agent, auth, error::ApiError, state::AppState};

/// Request body for `POST /v1/secrets/{sref}/use`.
#[derive(Deserialize)]
pub struct UseRequest {
    #[serde(default)]
    pub reason: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    /// Extra request headers. The bound credential header is added by the
    /// daemon and cannot be supplied here.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Request body, text.
    pub body: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?; // drop userinfo if any
    let host = host.trim_start_matches('[');
    let host = host.split(']').next()?; // ipv6 literal
    Some(host.split(':').next()?.to_ascii_lowercase())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) // CGNAT
                || v4.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                || v6.to_ipv4_mapped().map(|m| is_private(IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

/// Resolve the host and refuse anything that lands on a private or loopback
/// address, unless the deployment explicitly allows it. Resolution here and
/// again inside the HTTP client is a small TOCTOU window; acceptable for a
/// single-operator vault and noted in the threat model.
async fn ssrf_check(state: &AppState, host: &str) -> Result<(), ApiError> {
    if state.config.allow_private_upstreams {
        return Ok(());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private(ip) {
            return Err(ApiError::use_not_allowed(format!(
                "{host} is a private or loopback address"
            )));
        }
        return Ok(());
    }
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".internal")
        || host.ends_with(".local")
    {
        return Err(ApiError::use_not_allowed(format!(
            "{host} is not a public hostname"
        )));
    }
    let addrs = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|e| ApiError::upstream_failed(format!("could not resolve {host}: {e}")))?;
    let mut any = false;
    for a in addrs {
        any = true;
        if is_private(a.ip()) {
            return Err(ApiError::use_not_allowed(format!(
                "{host} resolves to a private or loopback address"
            )));
        }
    }
    if !any {
        return Err(ApiError::upstream_failed(format!("{host} did not resolve")));
    }
    Ok(())
}

/// `POST /v1/secrets/{sref}/use`
pub async fn use_secret(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    headers: HeaderMap,
    body: Result<Json<UseRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = body.map_err(|e| ApiError::invalid_request(e.body_text()))?;
    if req.reason.trim().is_empty() {
        return Err(ApiError::reason_required());
    }
    let reason = req.reason.trim().to_string();
    let t = auth::agent_token(&state, &headers)?;
    auth::require_live(&state, &t)?;

    // Policy, identical to a read, up to and including approval.
    let (detail, binding, value, remaining): (
        ItemDetail,
        bsc_store::model::UseBinding,
        zeroize::Zeroizing<Vec<u8>>,
        Option<u32>,
    ) = {
        let mut v = state.vault();
        let d = agent::in_scope(&v, &t, &sref)?;
        let binding = d
            .use_binding
            .clone()
            .ok_or_else(ApiError::use_not_configured)?;
        if agent::needs_approval(&v, &t, &d)? {
            let actor = Actor::Token { id: t.id.clone() };
            let a =
                v.request_approval(&t.id, &sref, &reason, state.config.approval_wait, &actor)?;
            drop(v);
            state.tick();
            return Err(ApiError::approval_pending(
                &a.id,
                a.expires_at,
                state.config.poll_interval,
            ));
        }
        // Binding gates before anything is decrypted.
        if !binding.allows_method(&req.method) {
            return Err(ApiError::use_not_allowed(format!(
                "method {} is not permitted for this item",
                req.method.to_ascii_uppercase()
            )));
        }
        if !binding.allows_url(&req.url, state.config.allow_private_upstreams) {
            return Err(ApiError::use_not_allowed(
                "the URL is outside this item's allowed patterns",
            ));
        }
        let remaining = v.consume_read(&t.id).map_err(|e| match e {
            StoreError::Invalid(_) => ApiError::quota_exhausted(),
            other => other.into(),
        })?;
        // The ledger sees a *use*, with the target, before decryption — the
        // store's read path still records the secret_read underneath.
        let host = host_of(&req.url).unwrap_or_default();
        let path = req
            .url
            .splitn(4, '/')
            .nth(3)
            .map(|p| format!("/{}", p.split('?').next().unwrap_or("")))
            .unwrap_or_else(|| "/".into());
        v.audit_event(
            &Actor::Token { id: t.id.clone() },
            "secret_used",
            Some(&sref),
            "ok",
            json!({ "reason": reason, "method": req.method.to_ascii_uppercase(), "host": host, "path": path }),
        )?;
        let actor = Actor::Token { id: t.id.clone() };
        let value = v.read(&sref, &actor, &format!("use_secret: {reason}"))?;
        (d, binding, value, remaining)
    };

    let host = host_of(&req.url)
        .ok_or_else(|| ApiError::invalid_request("url must be https://host/..."))?;
    ssrf_check(&state, &host).await?;

    // Build the outbound request. The credential header is templated from the
    // binding; the agent cannot set it or read it.
    let (hname, hvalue_tpl) = binding
        .header
        .split_once(':')
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .ok_or_else(|| ApiError::invalid_request("item's use header template is malformed"))?;
    let value_str = std::str::from_utf8(&value).map_err(|_| {
        ApiError::use_not_allowed("this item's value is binary and cannot be placed in a header")
    })?;
    let injected = zeroize::Zeroizing::new(hvalue_tpl.replace("{value}", value_str));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .https_only(!state.config.allow_private_upstreams)
        .user_agent(concat!("bsc/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(ApiError::internal)?;
    let method = reqwest::Method::from_bytes(req.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| ApiError::invalid_request("bad method"))?;
    let mut rb = client
        .request(method, &req.url)
        .header(hname.as_str(), injected.as_str());
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case(&hname)
            || k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("cookie")
        {
            continue; // the agent does not get to override the credential header or spoof host/cookies
        }
        rb = rb.header(k.as_str(), v.as_str());
    }
    if let Some(b) = &req.body {
        rb = rb.body(b.clone());
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| ApiError::upstream_failed(format!("request failed: {e}")))?;
    let status = resp.status();
    let resp_headers: serde_json::Map<String, serde_json::Value> = resp
        .headers()
        .iter()
        .filter(|(k, _)| {
            matches!(
                k.as_str(),
                "content-type"
                    | "content-length"
                    | "date"
                    | "x-request-id"
                    | "retry-after"
                    | "x-ratelimit-remaining"
            )
        })
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ApiError::upstream_failed(format!("reading response failed: {e}")))?;
    let cap = state.config.use_max_body;
    let truncated = bytes.len() > cap;
    let slice = &bytes[..bytes.len().min(cap)];
    let (text, b64) = crate::util::value_fields(slice);

    let mut out = (
        StatusCode::OK,
        Json(json!({
            "sref": detail.meta.id,
            "upstream_status": status.as_u16(),
            "upstream_headers": resp_headers,
            "body": text,
            "body_base64": b64,
            "truncated": truncated,
            "note": "the credential was injected by the vault; it is not in this response",
        })),
    )
        .into_response();
    out.headers_mut().insert(
        "Cache-Control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    if let Some(r) = remaining {
        if let Ok(v) = axum::http::HeaderValue::from_str(&r.to_string()) {
            out.headers_mut().insert("X-BSC-Reads-Remaining", v);
        }
    }
    Ok(out)
}

/// `PUT /v1/items/{sref}/use` — human sets or clears the binding.
#[derive(Deserialize)]
pub struct SetUse {
    pub binding: Option<bsc_store::model::UseBinding>,
}

pub async fn set_use(
    State(state): State<Arc<AppState>>,
    Path(sref): Path<String>,
    headers: HeaderMap,
    body: Result<Json<SetUse>, JsonRejection>,
) -> Result<Response, ApiError> {
    let actor = auth::human(&state, &headers, true)?;
    let Json(req) = body.map_err(|e| ApiError::invalid_request(e.body_text()))?;
    let d = state.vault().set_item_use(
        &sref,
        req.binding.as_ref(),
        state.config.allow_private_upstreams,
        &actor,
    )?;
    Ok(Json(json!({ "sref": d.meta.id, "use_binding": d.use_binding })).into_response())
}
