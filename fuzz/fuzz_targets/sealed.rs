#![no_main]
//! `Sealed::from_slice` is the first thing that touches any ciphertext read
//! from disk: nonce, ciphertext and tag split out of one byte string.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bsc_crypto::envelope::Sealed::from_slice(data);
});
