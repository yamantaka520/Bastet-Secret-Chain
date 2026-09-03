//! Behind a configured reverse proxy: the public Origin is accepted, the
//! cookie is Secure, logins are throttled per forwarded client, and the
//! ledger records that exposure was acknowledged. Without the flag nothing
//! changes from the loopback posture.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use bsc_crypto::kdf::KdfParams;
use bsc_daemon::{app, notify::RecordingNotifier, AppState, Config};
use bsc_store::Vault;
use reqwest::{header, StatusCode};
use serde_json::{json, Value};

const PW: &str = "correct horse battery staple";

async fn up(
    public_origin: Option<&str>,
) -> (
    tempfile::TempDir,
    String,
    reqwest::Client,
    Arc<AppState>,
    Arc<AtomicI64>,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        PW.as_bytes(),
        KdfParams::insecure_for_tests(*b"exposure-salt-01"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let c = clock.clone();
    let cfg = Config {
        public_origin: public_origin.map(str::to_string),
        ..Config::default()
    };
    let state = AppState::with(
        vault,
        cfg,
        Arc::new(move || c.load(Ordering::SeqCst)),
        Arc::new(RecordingNotifier::default()),
    );
    state.record_exposure();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(listener, app(st)).await.unwrap() });
    (
        dir,
        format!("http://{addr}"),
        reqwest::Client::new(),
        state,
        clock,
    )
}

async fn unseal(
    http: &reqwest::Client,
    base: &str,
    origin: Option<&str>,
    xff: Option<&str>,
    pw: &str,
) -> reqwest::Response {
    let mut r = http
        .post(format!("{base}/v1/vault/unseal"))
        .header("X-BSC-Client", "web")
        .json(&json!({ "passphrase": pw }));
    if let Some(o) = origin {
        r = r.header(header::ORIGIN, o);
    }
    if let Some(x) = xff {
        r = r.header("X-Forwarded-For", x);
    }
    r.send().await.unwrap()
}

#[tokio::test]
async fn without_the_flag_a_public_origin_is_still_refused_and_cookie_is_not_secure() {
    let (_d, base, http, _s, _c) = up(None).await;
    let r = unseal(&http, &base, Some("https://sec.example"), None, PW).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = unseal(&http, &base, Some("http://127.0.0.1:5173"), None, PW).await;
    assert_eq!(r.status(), StatusCode::OK);
    let sc = r
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!sc.contains("Secure"), "{sc}");
    assert!(sc.contains("SameSite=Strict") && sc.contains("HttpOnly"));
    // No acknowledgement was written.
    let st: Value = http
        .get(format!("{base}/v1/vault/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(st["public_origin"].is_null());
}

#[tokio::test]
async fn with_the_flag_public_origin_is_accepted_cookie_is_secure_and_exposure_is_recorded() {
    let (_d, base, http, _s, _c) = up(Some("https://sec.example")).await;
    // Other foreign origins are still refused.
    let r = unseal(&http, &base, Some("https://evil.example"), None, PW).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // The configured one (with or without trailing slash) is accepted.
    let r = unseal(
        &http,
        &base,
        Some("https://sec.example/"),
        Some("203.0.113.9"),
        PW,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    let sc = r
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(sc.contains("; Secure"), "{sc}");
    // Loopback still works for a local browser.
    let r = unseal(&http, &base, Some("http://127.0.0.1:8790"), None, PW).await;
    assert_eq!(r.status(), StatusCode::OK);

    let cookie = sc.split(';').next().unwrap().to_string();
    let st: Value = http
        .get(format!("{base}/v1/vault/status"))
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["public_origin"], "https://sec.example");
    let audit: Value = http
        .get(format!("{base}/v1/audit?limit=1000"))
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ack = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "exposure_acknowledged")
        .expect("exposure_acknowledged in ledger");
    assert_eq!(ack["actor"], "system");
    assert_eq!(ack["meta"]["public_origin"], "https://sec.example");
}

#[tokio::test]
async fn login_attempts_are_throttled_per_forwarded_client_only_when_exposed() {
    let (_d, base, http, _s, clock) = up(Some("https://sec.example")).await;
    let o = Some("https://sec.example");
    for i in 0..5 {
        let r = unseal(&http, &base, o, Some("198.51.100.7"), "wrong").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    // Sixth attempt from the same client is refused before the KDF runs — even with the right passphrase.
    let r = unseal(&http, &base, o, Some("198.51.100.7"), PW).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"], "rate_limited");
    assert_eq!(v["retry_after"], 600);
    // A different client is unaffected.
    let r = unseal(&http, &base, o, Some("198.51.100.8"), PW).await;
    assert_eq!(r.status(), StatusCode::OK);
    // The window passes.
    clock.fetch_add(600, Ordering::SeqCst);
    let r = unseal(&http, &base, o, Some("198.51.100.7"), PW).await;
    assert_eq!(r.status(), StatusCode::OK);
    // Only the first hop of X-Forwarded-For counts.
    for _ in 0..5 {
        unseal(&http, &base, o, Some("192.0.2.1, 10.0.0.1"), "wrong").await;
    }
    let r = unseal(&http, &base, o, Some("192.0.2.1, 10.0.0.99"), PW).await;
    assert_eq!(
        r.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "spoofing later hops must not evade"
    );
}

#[tokio::test]
async fn without_the_flag_x_forwarded_for_is_ignored_and_all_local_attempts_share_one_bucket() {
    let (_d, base, http, _s, _c) = up(None).await;
    for _ in 0..5 {
        unseal(&http, &base, None, Some("198.51.100.7"), "wrong").await;
    }
    // A "different" forwarded client is still the same loopback bucket: the
    // header is untrusted when no proxy is declared.
    let r = unseal(&http, &base, None, Some("198.51.100.8"), PW).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
}
