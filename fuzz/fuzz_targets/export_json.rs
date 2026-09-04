#![no_main]
//! The JSON inside a bundle, once decrypted. Authenticated, so this is
//! defence in depth: a bug here needs the export passphrase first.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<bsc_store::export::Bundle>(data);
});
