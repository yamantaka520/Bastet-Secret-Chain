//! The daemon embeds `ui/dist`. When the UI has not been built (a fresh
//! checkout, a CI job that only runs `cargo test`), embed a one-page notice
//! instead of failing to compile — the API is fully usable without the UI.

use std::{fs, path::Path, process::Command};

/// Short git sha for the build, so `/v1/vault/status`, `bsc --version` and
/// `bsc doctor` can say which build is running. Order: `BSC_BUILD_SHA` (set
/// explicitly), `GITHUB_SHA` (CI), `git rev-parse` (local), else `unknown`.
fn build_sha() -> String {
    for var in ["BSC_BUILD_SHA", "GITHUB_SHA"] {
        println!("cargo:rerun-if-env-changed={var}");
        if let Ok(v) = std::env::var(var) {
            let v = v.trim();
            if v.len() >= 7 {
                return v[..7].to_string();
            }
        }
    }
    let git_head = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.git/HEAD");
    if git_head.exists() {
        println!("cargo:rerun-if-changed={}", git_head.display());
    }
    Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// Build date as UTC `YYYY-MM-DD`; honours `SOURCE_DATE_EPOCH` for
/// reproducible builds.
fn build_date() -> String {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let secs: i64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });
    // Civil-from-days (Howard Hinnant), enough for a date stamp.
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn main() {
    println!("cargo:rustc-env=BSC_BUILD_SHA={}", build_sha());
    println!("cargo:rustc-env=BSC_BUILD_DATE={}", build_date());
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    let index = dist.join("index.html");
    if !index.exists() {
        fs::create_dir_all(&dist).expect("create ui/dist");
        fs::write(
            &index,
            "<!doctype html><meta charset=utf-8><title>Bastet Secret Chain</title>\
<body style=\"font:16px system-ui;padding:3rem;max-width:40rem;margin:auto\">\
<h1>🔐⛓️ Bastet Secret Chain</h1><p>The daemon is running, but the Web UI was not \
built into this binary. Run <code>npm --prefix ui ci && npm --prefix ui run build</code> \
and rebuild, or use the HTTP API at <code>/v1</code>.</p>",
        )
        .expect("write placeholder index.html");
    }
}
