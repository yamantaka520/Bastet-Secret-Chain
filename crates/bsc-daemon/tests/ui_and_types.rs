//! M3: every item type round-trips through the human surface the UI uses,
//! and the daemon serves the embedded single-page app with the right headers.

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

async fn up() -> (tempfile::TempDir, String, reqwest::Client, String) {
    let dir = tempfile::TempDir::new().unwrap();
    let vault = Vault::create_with_params(
        &dir.path().join("v.bsc"),
        PW.as_bytes(),
        KdfParams::insecure_for_tests(*b"ui-types-salt-01"),
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let state = AppState::with(
        vault,
        Config::default(),
        Arc::new(move || clock.load(Ordering::SeqCst)),
        Arc::new(RecordingNotifier::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{base}/v1/vault/unseal"))
        .header("X-BSC-Client", "web")
        .json(&json!({ "passphrase": PW }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = r
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    (dir, base, http, cookie)
}

/// Exactly what the UI does for each type: create → appears in list with
/// name/path/tags → detail → the copy button's URL is a reference → reveal
/// (with passphrase where the type defaults to approval-required) → per-item
/// audit shows the read.
#[tokio::test]
async fn every_item_type_round_trips_through_the_human_surface() {
    let (_d, base, http, cookie) = up().await;
    let human = |m: reqwest::Method, p: &str| {
        http.request(m, format!("{base}{p}"))
            .header(header::COOKIE, &cookie)
            .header("X-BSC-Client", "web")
    };

    let cases: [(&str, &str, bool); 8] = [
        ("login", "alice / hunter2 / otpauth://totp/x", false),
        ("api_key", "sk_test_not_real", false),
        ("cloud_key", "AKIA_FAKE / secret", true),
        (
            "service_account",
            "{\"type\":\"service_account\",\"project_id\":\"demo\"}",
            true,
        ),
        (
            "oauth",
            "{\"client_id\":\"x\",\"client_secret\":\"y\"}",
            false,
        ),
        (
            "ssh_key",
            "-----BEGIN OPENSSH FAKE-----\nabc\n-----END-----",
            false,
        ),
        ("certificate", "-----BEGIN CERT FAKE-----\nxyz", true),
        ("file", "", false), // binary below
    ];
    let binary_b64 = "AAECAwT/"; // 0x00 0x01 0x02 0x03 0x04 0xff

    for (ty, value, approval_default) in cases {
        let body = if ty == "file" {
            json!({ "path": format!("prod/{ty}"), "name": format!("{ty}-item"), "type": ty, "tags": ["e2e", ty], "env": "prod", "value_base64": binary_b64 })
        } else {
            json!({ "path": format!("prod/{ty}"), "name": format!("{ty}-item"), "type": ty, "tags": ["e2e", ty], "env": "prod", "value": value })
        };
        let r = human(reqwest::Method::POST, "/v1/items")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::CREATED,
            "{ty}: {}",
            r.text().await.unwrap()
        );
        let created: Value = r.json().await.unwrap();
        let sref = created["sref"].as_str().unwrap().to_string();
        assert!(
            sref.starts_with("sref_") && sref.len() == 27,
            "{ty}: {sref}"
        );
        assert_eq!(created["type"], ty);
        assert_eq!(
            created["approval_required"], approval_default,
            "{ty} default approval"
        );
        assert_eq!(created["name"], format!("{ty}-item"));
        assert_eq!(created["tags"], json!(["e2e", ty]));

        // Listed with decrypted name/path/tags.
        let list: Value = human(reqwest::Method::GET, "/v1/items")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let row = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["sref"] == sref)
            .expect("listed");
        assert_eq!(row["path"], format!("prod/{ty}"));

        // The copy button's URL identifies but grants nothing.
        let r = http
            .get(format!("{base}/v1/secrets/{sref}?reason=copied-url-alone"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "{ty}: a pasted reference must not release"
        );
        let e: Value = r.json().await.unwrap();
        assert_eq!(e["error"], "unauthorized");

        // Reveal: passphrase only where approval is required.
        let r = human(reqwest::Method::POST, &format!("/v1/items/{sref}/reveal"))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let ok_resp = if approval_default {
            assert_eq!(
                r.status(),
                StatusCode::BAD_REQUEST,
                "{ty} must demand the passphrase"
            );
            human(reqwest::Method::POST, &format!("/v1/items/{sref}/reveal"))
                .json(&json!({ "passphrase": PW }))
                .send()
                .await
                .unwrap()
        } else {
            r
        };
        assert_eq!(ok_resp.status(), StatusCode::OK, "{ty}");
        assert_eq!(
            ok_resp
                .headers()
                .get("cache-control")
                .map(|h| h.to_str().unwrap()),
            Some("no-store")
        );
        let v: Value = ok_resp.json().await.unwrap();
        if ty == "file" {
            assert!(v["value"].is_null());
            assert_eq!(v["value_base64"], binary_b64);
        } else {
            assert_eq!(v["value"], value);
        }

        // Per-item audit (the drawer's tab) shows the reveal as a human read.
        let a: Value = human(
            reqwest::Method::GET,
            &format!("/v1/audit?subject={sref}&limit=100"),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        let recs = a["records"].as_array().unwrap();
        assert!(recs.iter().any(|r| r["action"] == "item_created"), "{ty}");
        let read = recs
            .iter()
            .find(|r| r["action"] == "secret_read")
            .expect("reveal recorded");
        assert!(read["actor"].as_str().unwrap().starts_with("human:"));
        assert_eq!(read["meta"]["reason"], "revealed in UI");
        for r in recs {
            assert!(
                !r.to_string()
                    .contains(value.split(' ').next().unwrap_or("§"))
                    || value.is_empty(),
                "{ty}: value in ledger"
            );
        }
    }

    // Eight distinct types, eight items, all filterable by the shared tag.
    let list: Value = human(reqwest::Method::GET, "/v1/items")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 8);
}

#[tokio::test]
async fn embedded_ui_is_served_with_hardening_headers_and_v1_stays_json() {
    let (_d, base, http, _cookie) = up().await;

    let r = http.get(&base).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let csp = r
        .headers()
        .get("content-security-policy")
        .expect("CSP on the document")
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(r.headers().get("referrer-policy").unwrap(), "no-referrer");
    let html = r.text().await.unwrap();
    assert!(html.contains("<title>Bastet Secret Chain</title>"));
    // Either the built app (root div + module script) or the explicit not-built notice.
    assert!(
        html.contains("id=\"root\"") || html.contains("was not built"),
        "{html}"
    );

    // Client-side routes fall back to the document.
    let r = http
        .get(format!("{base}/anything/deep"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));

    // Unknown API routes keep the error contract.
    let r = http
        .get(format!("{base}/v1/does-not-exist"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let e: Value = r.json().await.unwrap();
    assert_eq!(e["error"], "not_found");
    assert!(e["do_not"].is_string());

    // Built assets, when present, are immutable-cached.
    if html.contains("/assets/") {
        let start = html.find("/assets/").unwrap();
        let end = html[start..].find('"').unwrap();
        let asset = &html[start..start + end];
        let r = http.get(format!("{base}{asset}")).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{asset}");
        assert!(r
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("immutable"));
    }
}
