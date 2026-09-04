#![no_main]
//! Anchor files live outside the vault, on purpose — which means `bsc audit`
//! parses a file that something else on the host may have written.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let _ = serde_json::from_str::<bsc_store::audit::Anchor>(line);
        }
    }
});
