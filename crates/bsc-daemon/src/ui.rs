//! Serves the embedded single-page app. Anything under `/v1` that reached the
//! fallback is an unknown API route and answers in the error contract; every
//! other path gets the SPA (with `index.html` for client-side routes).

use axum::{
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

use crate::error::ApiError;

#[derive(RustEmbed)]
#[folder = "../../ui/dist/"]
struct Dist;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

fn file(path: &str) -> Option<Response> {
    let f = Dist::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut resp = (StatusCode::OK, f.data.into_owned()).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.essence_str())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    if path.starts_with("assets/") {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    } else {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
        h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        h.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    Some(resp)
}

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("v1/") || path == "v1" {
        return ApiError::not_found("Route").into_response();
    }
    if !path.is_empty() {
        if let Some(r) = file(path) {
            return r;
        }
    }
    file("index.html").unwrap_or_else(|| (StatusCode::NOT_FOUND, "UI not built").into_response())
}
