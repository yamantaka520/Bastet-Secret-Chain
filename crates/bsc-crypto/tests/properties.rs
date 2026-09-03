//! Property tests over the envelope construction.

use bsc_crypto::{
    blind_index::{tokens, IndexKey},
    envelope::{
        check_verifier, make_verifier, open_body, open_field, seal_body, seal_field, Aad, Sealed,
        WrappedDek,
    },
    kdf::{KdfParams, Kek},
    CryptoError,
};
use proptest::prelude::*;

fn kek(seed: u8) -> Kek {
    Kek::from_bytes([seed; 32])
}

fn arb_aad() -> impl Strategy<Value = (String, u32, String)> {
    ("[a-z0-9_]{0,24}", any::<u32>(), "[a-z/]{1,12}")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn body_roundtrips(pt in proptest::collection::vec(any::<u8>(), 0..4096), (id, ver, field) in arb_aad()) {
        let k = kek(7);
        let aad = Aad { item_id: &id, version: ver, field: &field };
        let (w, s) = seal_body(&k, &aad, &pt).unwrap();
        let back = open_body(&k, &aad, &w, &s).unwrap();
        prop_assert_eq!(&*back, &pt[..]);
        prop_assert_eq!(s.plaintext_len(), pt.len());
    }

    #[test]
    fn field_roundtrips(pt in proptest::collection::vec(any::<u8>(), 0..512), (id, ver, field) in arb_aad()) {
        let k = kek(9);
        let aad = Aad { item_id: &id, version: ver, field: &field };
        let s = seal_field(&k, &aad, &pt).unwrap();
        let back = open_field(&k, &aad, &s).unwrap();
        prop_assert_eq!(&*back, &pt[..]);
    }

    #[test]
    fn sealed_blob_roundtrips(pt in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let k = kek(3);
        let aad = Aad { item_id: "x", version: 1, field: "body" };
        let s = seal_field(&k, &aad, &pt).unwrap();
        let bytes = s.to_vec();
        let parsed = Sealed::from_slice(&bytes).unwrap();
        prop_assert_eq!(parsed, s);
    }

    #[test]
    fn wrong_kek_fails(pt in proptest::collection::vec(any::<u8>(), 1..256)) {
        let aad = Aad { item_id: "it", version: 1, field: "body" };
        let (w, s) = seal_body(&kek(1), &aad, &pt).unwrap();
        prop_assert_eq!(open_body(&kek(2), &aad, &w, &s).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn different_item_fails(pt in proptest::collection::vec(any::<u8>(), 1..256), a in "[a-z]{1,8}", b in "[a-z]{1,8}") {
        prop_assume!(a != b);
        let k = kek(4);
        let (w, s) = seal_body(&k, &Aad { item_id: &a, version: 1, field: "body" }, &pt).unwrap();
        prop_assert_eq!(
            open_body(&k, &Aad { item_id: &b, version: 1, field: "body" }, &w, &s).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn different_version_fails(pt in proptest::collection::vec(any::<u8>(), 1..256), v in any::<u32>()) {
        let k = kek(5);
        let (w, s) = seal_body(&k, &Aad { item_id: "it", version: v, field: "body" }, &pt).unwrap();
        prop_assert_eq!(
            open_body(&k, &Aad { item_id: "it", version: v.wrapping_add(1), field: "body" }, &w, &s).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn flipped_bit_fails(pt in proptest::collection::vec(any::<u8>(), 1..256), pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let k = kek(6);
        let aad = Aad { item_id: "it", version: 1, field: "body" };
        let (w, s) = seal_body(&k, &aad, &pt).unwrap();
        let mut bytes = s.to_vec();
        let i = pos.index(bytes.len());
        bytes[i] ^= 1 << bit;
        let tampered = Sealed::from_slice(&bytes).unwrap();
        prop_assert_eq!(open_body(&k, &aad, &w, &tampered).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn tampered_wrap_fails(pt in proptest::collection::vec(any::<u8>(), 1..256), pos in any::<prop::sample::Index>()) {
        let k = kek(8);
        let aad = Aad { item_id: "it", version: 1, field: "body" };
        let (w, s) = seal_body(&k, &aad, &pt).unwrap();
        let mut wb = w.as_bytes().to_vec();
        let i = pos.index(wb.len());
        wb[i] ^= 0x80;
        prop_assert_eq!(open_body(&k, &aad, &WrappedDek::from_bytes(wb), &s).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn body_and_wrap_are_not_interchangeable(pt in proptest::collection::vec(any::<u8>(), 32..33)) {
        // A 32-byte body produces a body ciphertext the same length as a
        // wrapped DEK. Feeding one where the other belongs must still fail.
        let k = kek(10);
        let aad = Aad { item_id: "it", version: 1, field: "body" };
        let (w, s) = seal_body(&k, &aad, &pt).unwrap();
        let swapped_wrap = WrappedDek::from_bytes(s.to_vec());
        let swapped_body = Sealed::from_slice(w.as_bytes()).unwrap();
        prop_assert!(open_body(&k, &aad, &swapped_wrap, &swapped_body).is_err());
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce(pt in proptest::collection::vec(any::<u8>(), 0..64)) {
        let k = kek(11);
        let aad = Aad { item_id: "it", version: 1, field: "body" };
        let a = seal_field(&k, &aad, &pt).unwrap().to_vec();
        let b = seal_field(&k, &aad, &pt).unwrap().to_vec();
        prop_assert_ne!(a, b);
    }

    #[test]
    fn aad_encoding_is_injective((id1, v1, f1) in arb_aad(), (id2, v2, f2) in arb_aad()) {
        let a = Aad { item_id: &id1, version: v1, field: &f1 }.to_bytes();
        let b = Aad { item_id: &id2, version: v2, field: &f2 }.to_bytes();
        let same = id1 == id2 && v1 == v2 && f1 == f2;
        prop_assert_eq!(a == b, same);
    }

    #[test]
    fn tokens_are_lowercase_unique_nonempty(s in "[A-Za-z0-9 /_.-]{0,64}") {
        let t = tokens(&s);
        for (i, tok) in t.iter().enumerate() {
            prop_assert!(!tok.is_empty());
            prop_assert_eq!(tok, &tok.to_lowercase());
            prop_assert!(!t[..i].contains(tok));
        }
    }

    #[test]
    fn blind_index_is_field_scoped(tok in "[a-z0-9]{1,16}") {
        let idx = IndexKey::derive(&kek(12));
        prop_assert_ne!(idx.tag("name", &tok), idx.tag("path", &tok));
    }

    #[test]
    fn blind_index_keys_differ_per_kek(tok in "[a-z0-9]{1,16}", a in any::<u8>(), b in any::<u8>()) {
        prop_assume!(a != b);
        prop_assert_ne!(
            IndexKey::derive(&kek(a)).tag("name", &tok),
            IndexKey::derive(&kek(b)).tag("name", &tok)
        );
    }
}

#[test]
fn verifier_accepts_right_key_and_rejects_wrong() {
    let k = kek(20);
    let v = make_verifier(&k).unwrap();
    assert!(check_verifier(&k, &v));
    assert!(!check_verifier(&kek(21), &v));
    let mut bytes = v.to_vec();
    bytes[30] ^= 1;
    assert!(!check_verifier(&k, &Sealed::from_slice(&bytes).unwrap()));
}

#[test]
fn kdf_rejects_weak_production_params() {
    let salt = [0u8; 16];
    assert_eq!(
        KdfParams::new(1024, 3, 1, salt).unwrap_err(),
        CryptoError::Parameter("m_cost below minimum")
    );
    assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 0, 1, salt).is_err());
    assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 0, salt).is_err());
    assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1, salt).is_ok());
}

#[test]
fn kdf_is_deterministic_and_salt_sensitive() {
    let p1 = KdfParams::insecure_for_tests(*b"salt-salt-salt-1");
    let p2 = KdfParams::insecure_for_tests(*b"salt-salt-salt-2");
    let a = Kek::derive(b"pw", &p1).unwrap();
    let b = Kek::derive(b"pw", &p1).unwrap();
    let c = Kek::derive(b"pw", &p2).unwrap();
    let aad = Aad {
        item_id: "",
        version: 0,
        field: "t",
    };
    let s = seal_field(&a, &aad, b"x").unwrap();
    assert!(open_field(&b, &aad, &s).is_ok());
    assert!(open_field(&c, &aad, &s).is_err());
}

#[test]
fn short_blob_is_rejected() {
    assert_eq!(
        Sealed::from_slice(&[0u8; 39]).unwrap_err(),
        CryptoError::Encoding
    );
    assert!(Sealed::from_slice(&[0u8; 40]).is_ok());
}

#[test]
fn secret_types_do_not_print_contents() {
    let k = kek(0xAB);
    assert_eq!(format!("{k:?}"), "Kek(<redacted>)");
    let idx = IndexKey::derive(&k);
    assert_eq!(format!("{idx:?}"), "IndexKey(<redacted>)");
    let (w, s) = seal_body(
        &k,
        &Aad {
            item_id: "i",
            version: 1,
            field: "body",
        },
        b"pt",
    )
    .unwrap();
    assert_eq!(format!("{w:?}"), "WrappedDek(<opaque>)");
    assert!(!format!("{s:?}").contains("ct:"));
}
