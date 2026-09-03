//! Regenerates the deterministic known-answer values pinned in
//! `tests/vectors.rs`. Run with `cargo run -p bsc-crypto --example gen_vectors`.
//!
//! Only the *deterministic* parts of the construction can be pinned: the KDF
//! output for fixed inputs, the AAD encoding, and blind-index tags. Sealing
//! uses a random nonce, so it is covered by decrypt-of-fixed-ciphertext tests
//! instead, whose ciphertexts are also printed here once.

use bsc_crypto::{
    blind_index::IndexKey,
    envelope::{seal_body, seal_field, Aad},
    kdf::{KdfParams, Kek},
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let salt = *b"bsc-test-salt-01";
    let params = KdfParams::insecure_for_tests(salt);
    let kek = Kek::derive(b"correct horse battery staple", &params).unwrap();

    let aad = Aad {
        item_id: "it_01",
        version: 1,
        field: "body",
    };
    println!("aad_hex = {}", hex(&aad.to_bytes()));

    let idx = IndexKey::derive(&kek);
    println!("tag(name, \"aws\") = {}", hex(&idx.tag("name", "aws")));
    println!("tag(path, \"prod\") = {}", hex(&idx.tag("path", "prod")));

    let (wrapped, body) = seal_body(&kek, &aad, b"the secret body").unwrap();
    println!("wrapped_dek_hex = {}", hex(wrapped.as_bytes()));
    println!("body_hex = {}", hex(&body.to_vec()));

    let name_aad = Aad {
        item_id: "it_01",
        version: 0,
        field: "name",
    };
    let name = seal_field(&kek, &name_aad, b"aws-billing").unwrap();
    println!("name_hex = {}", hex(&name.to_vec()));
}
