//! The Bastet Secret Chain daemon.
//!
//! One axum router with two surfaces that share one authorization, quota,
//! approval, and audit implementation:
//!
//! - **Agent surface** (`Authorization: Bearer bsct_…`): read-only, every
//!   value-releasing call needs a `reason`, blocked reads pend as `202`.
//! - **Human surface** (session cookie, loopback): vault lifecycle, items,
//!   tokens, task sessions, approvals, ledger.
//!
//! The wire shape is fixed by `docs/API_CONTRACT.md`; the error table there is
//! `error::Code`. The MCP server in `bsc-mcp` is a client of this API and has
//! no authority of its own.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// `ApiError` is a complete HTTP response — code, prose, status, extras — and
// every handler returns it. Boxing it on each path would add noise for no
// measurable gain on a loopback daemon.
#![allow(clippy::result_large_err)]

mod agent;
mod auth;
pub mod error;
mod human;
pub mod notify;
pub mod state;
mod ui;
mod util;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    routing::{delete, get, post},
    Router,
};

pub use state::{AppState, Config};

/// Build the router. Separated from [`serve`] so tests can bind their own port.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        // ---- agent surface
        .route("/v1/secrets", get(agent::list))
        .route("/v1/secrets/:sref", get(agent::release_current))
        .route("/v1/secrets/:sref/versions/:n", get(agent::release_version))
        .route("/v1/access-requests", post(agent::request_access))
        .route("/v1/access-requests/:apr", get(agent::check_access))
        .route("/v1/token/renew", post(agent::renew))
        .route("/v1/token", get(agent::whoami))
        // ---- human surface
        .route("/v1/vault/unseal", post(human::unseal))
        .route("/v1/vault/seal", post(human::seal))
        .route("/v1/vault/status", get(human::status))
        .route("/v1/items", get(human::list_items).post(human::create_item))
        .route(
            "/v1/items/:sref",
            get(human::item_detail).patch(human::patch_item),
        )
        .route("/v1/items/:sref/versions", post(human::add_version))
        .route("/v1/items/:sref/reveal", post(human::reveal))
        .route(
            "/v1/tokens",
            get(human::list_tokens).post(human::mint_token),
        )
        .route("/v1/tokens/:tok", delete(human::revoke_token))
        .route(
            "/v1/sessions",
            get(human::list_sessions).post(human::open_session),
        )
        .route("/v1/sessions/:ses", delete(human::close_session))
        .route("/v1/approvals", get(human::list_approvals))
        .route("/v1/approvals/:apr/approve", post(human::approve))
        .route("/v1/approvals/:apr/deny", post(human::deny))
        .route("/v1/audit", get(human::audit_read))
        .route("/v1/audit/verify", get(human::audit_verify))
        .route("/v1/handoff-links", post(human::handoff_disabled))
        // ---- the embedded Web UI; unknown /v1 paths still answer in JSON
        .fallback(ui::serve)
        .with_state(state)
}

/// Bind and serve until `shutdown` resolves. Refuses any non-loopback bind:
/// remote exposure is gated behind the master plan §4.4 requirements, none of
/// which are implemented yet.
pub async fn serve(
    state: Arc<AppState>,
    bind: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    if !bind.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("refusing to bind {bind}: only loopback is permitted until remote exposure is implemented"),
        ));
    }
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "bsc daemon listening");
    match &state.config.public_origin {
        Some(o) => {
            eprintln!(
                "Bastet Secret Chain UI: http://{bind}/  (public origin {o} via reverse proxy)"
            );
            tracing::warn!(public_origin = %o, "exposure acknowledged: a reverse proxy is expected to front this daemon");
            state.record_exposure();
        }
        None => eprintln!("Bastet Secret Chain UI: http://{bind}/"),
    }
    state.spawn_ticker();
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown)
        .await
}
