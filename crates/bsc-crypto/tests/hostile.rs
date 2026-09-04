//! What happens when the bytes come from somebody else.
//!
//! A break-glass bundle is meant to be handed to a successor, so `open_bundle`
//! parses a file this program did not write. Its header carries the Argon2
//! parameters, which means an attacker picks how much memory and time the
//! reader spends — unless the reader says no first.

use std::time::{Duration, Instant};

use bsc_crypto::{
    bundle::{open_bundle, seal_bundle},
    kdf::KdfParams,
};

const PW: &[u8] = b"export passphrase";
const HEADER_LEN: usize = 5 + 16 + 12;

fn good() -> Vec<u8> {
    seal_bundle(
        PW,
        &KdfParams::insecure_for_tests(*b"hostile-salt-001"),
        b"the plaintext",
    )
    .unwrap()
}

/// Overwrite one little-endian u32 in the header.
fn with_cost(field: usize, value: u32) -> Vec<u8> {
    let mut b = good();
    let at = 5 + 16 + field * 4;
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    b
}

#[test]
fn a_bundle_cannot_dictate_how_much_memory_the_reader_spends() {
    for (name, bytes) in [
        ("m_cost = u32::MAX", with_cost(0, u32::MAX)),
        ("m_cost = 2 GiB", with_cost(0, 2 * 1024 * 1024)),
        ("t_cost = u32::MAX", with_cost(1, u32::MAX)),
        ("p_cost = u32::MAX", with_cost(2, u32::MAX)),
        ("m_cost = 0", with_cost(0, 0)),
        ("t_cost = 0", with_cost(1, 0)),
        ("p_cost = 0", with_cost(2, 0)),
    ] {
        let started = Instant::now();
        assert!(open_bundle(PW, &bytes).is_err(), "{name} was accepted");
        // The point is not only that it fails: it must fail before doing the
        // work the header asked for.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{name} took {:?} to refuse — the parameters reached the KDF",
            started.elapsed()
        );
    }
}

#[test]
fn the_ceiling_leaves_room_for_real_parameters() {
    // Production is 64 MiB / 3 / 4; a future default well above it still opens.
    let params = KdfParams::new(
        KdfParams::MIN_M_COST_KIB,
        KdfParams::MAX_T_COST,
        KdfParams::MAX_P_COST,
        *b"hostile-salt-002",
    )
    .unwrap();
    let b = seal_bundle(PW, &params, b"still fine").unwrap();
    assert_eq!(open_bundle(PW, &b).unwrap().as_slice(), b"still fine");
}

#[test]
fn truncation_and_garbage_are_refused_without_panicking() {
    let b = good();
    for n in 0..=b.len() {
        assert!(open_bundle(PW, &b[..n]).is_err() || n == b.len());
    }
    for junk in [
        vec![],
        vec![0u8; HEADER_LEN],
        vec![0xff; HEADER_LEN + 1],
        b"BSCX1".to_vec(),
        b"BSCX2 and then some padding to reach the header length ....".to_vec(),
    ] {
        assert!(open_bundle(PW, &junk).is_err());
    }
}

#[test]
fn every_single_byte_is_covered_by_the_tag() {
    let b = good();
    for i in 0..b.len() {
        let mut bad = b.clone();
        bad[i] ^= 0x01;
        assert!(
            open_bundle(PW, &bad).is_err(),
            "flipping byte {i} produced a bundle that still opened"
        );
    }
}

#[test]
fn the_right_passphrase_still_works_and_a_wrong_one_does_not() {
    let b = good();
    assert_eq!(open_bundle(PW, &b).unwrap().as_slice(), b"the plaintext");
    assert!(open_bundle(b"not the passphrase", &b).is_err());
}
