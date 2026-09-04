#![no_main]
//! A break-glass bundle is designed to be handed between people, so its bytes
//! are the most likely to arrive from somewhere untrusted.
//!
//! The header's KDF cost fields are clamped here so the fuzzer spends its time
//! in the parser rather than in Argon2; the real ceiling that rejects absurd
//! costs is tested in `crates/bsc-crypto/tests/hostile.rs`.
use libfuzzer_sys::fuzz_target;

const HEADER_LEN: usize = 5 + 16 + 12;

fuzz_target!(|data: &[u8]| {
    let mut bytes = data.to_vec();
    if bytes.len() >= HEADER_LEN {
        let base = 5 + 16;
        for (i, v) in [64u32, 1, 1].iter().enumerate() {
            let at = base + i * 4;
            bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    let _ = bsc_crypto::bundle::open_bundle(b"fuzz passphrase", &bytes);
});
