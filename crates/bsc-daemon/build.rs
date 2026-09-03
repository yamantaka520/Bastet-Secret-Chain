//! The daemon embeds `ui/dist`. When the UI has not been built (a fresh
//! checkout, a CI job that only runs `cargo test`), embed a one-page notice
//! instead of failing to compile — the API is fully usable without the UI.

use std::{fs, path::Path};

fn main() {
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
