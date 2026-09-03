//! Known-answer vectors for the deterministic parts of the format.
//!
//! Regenerate with `cargo run -p bsc-crypto --example gen_vectors`. If a
//! value here changes, the on-disk format changed: every existing vault would
//! stop decrypting. That needs a migration, not a test update.

use bsc_crypto::{
    blind_index::IndexKey,
    envelope::{open_body, open_field, Aad, Sealed, WrappedDek},
    kdf::{KdfParams, Kek},
};

const SALT: [u8; 16] = *b"bsc-test-salt-01";
const PASSPHRASE: &[u8] = b"correct horse battery staple";

fn kek() -> Kek {
    Kek::derive(PASSPHRASE, &KdfParams::insecure_for_tests(SALT)).unwrap()
}

#[test]
fn aad_encoding_is_pinned() {
    let aad = Aad {
        item_id: "it_01",
        version: 1,
        field: "body",
    };
    assert_eq!(
        hex::encode(aad.to_bytes()),
        "050000006273632f310500000069745f30310100000004000000626f6479"
    );
}

#[test]
fn blind_index_tags_are_pinned() {
    // Pins Argon2id(passphrase, salt, params) → HKDF → HMAC end to end.
    let idx = IndexKey::derive(&kek());
    assert_eq!(
        hex::encode(idx.tag("name", "aws")),
        "fe9529c8e2ef072a16d78d5f90152e0b"
    );
    assert_eq!(
        hex::encode(idx.tag("path", "prod")),
        "4651110e1415ddfe20eaaaa2a015e998"
    );
}

#[test]
fn pinned_body_ciphertext_decrypts() {
    // Ciphertext produced once by gen_vectors. Decrypting it pins the KDF
    // output, the AAD binding, and the wrap/unwrap layout together without
    // ever printing key bytes.
    let wrapped = WrappedDek::from_bytes(
        hex::decode(
            "8ed0a915e842e8b06e55ec8e4a0704d759704158695789fc325a6b61c05b1b4117e7dfc6457cb260d6feb94f11e7e82687e7baca6c6c85790ca09e3c5f63221e26c2d276c72d3117",
        )
        .unwrap(),
    );
    let body = Sealed::from_slice(
        &hex::decode(
            "aa9a27cbe79792ddf4a250f9e4867aca9e40ea67f0266c8ac55c4fe1d4638edb1b94156516e961b1142938c1f2266f74fef50a358413d4",
        )
        .unwrap(),
    )
    .unwrap();
    let aad = Aad {
        item_id: "it_01",
        version: 1,
        field: "body",
    };
    let pt = open_body(&kek(), &aad, &wrapped, &body).unwrap();
    assert_eq!(&*pt, b"the secret body");

    // Same blob under a different passphrase must fail.
    let wrong = Kek::derive(b"incorrect horse", &KdfParams::insecure_for_tests(SALT)).unwrap();
    assert!(open_body(&wrong, &aad, &wrapped, &body).is_err());
}

#[test]
fn pinned_field_ciphertext_decrypts() {
    let name = Sealed::from_slice(
        &hex::decode(
            "db4060a06c1800d2f9904cfe2792227512fbac3b92995c8546b4f9cb0415ae5bc61ea46583080ad67aefef687858d08fc92484",
        )
        .unwrap(),
    )
    .unwrap();
    let aad = Aad {
        item_id: "it_01",
        version: 0,
        field: "name",
    };
    let pt = open_field(&kek(), &aad, &name).unwrap();
    assert_eq!(&*pt, b"aws-billing");
    // Same field ciphertext presented as another item's name must fail.
    let other = Aad {
        item_id: "it_02",
        ..aad
    };
    assert!(open_field(&kek(), &other, &name).is_err());
}
