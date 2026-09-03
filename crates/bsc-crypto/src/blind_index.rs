//! Keyed token hashes for searching encrypted names without decrypting them.
//!
//! The index key is derived from the KEK with HKDF and a fixed info string,
//! so it is distinct from the encryption key but needs no separate storage.
//! Each searchable text is split into lowercase tokens, and each token is
//! HMAC'd with the field name to a 16-byte tag. The store keeps the tags; a
//! search computes the tag for the query token and looks it up.
//!
//! This is exact-token search only. Substring and fuzzy matching require an
//! unsealed vault and are out of scope for the index by design.

use core::fmt;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{kdf::Kek, KEY_LEN};

/// Length of an index tag. 128 bits is far beyond collision concern for a
/// single-operator vault and keeps the index table small.
pub const TAG_LEN: usize = 16;

const INFO: &[u8] = b"bsc/1 blind-index";

/// Key for the blind index. Derived, never stored, zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct IndexKey([u8; KEY_LEN]);

impl fmt::Debug for IndexKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IndexKey(<redacted>)")
    }
}

impl IndexKey {
    /// Derive the index key from the KEK.
    pub fn derive(kek: &Kek) -> IndexKey {
        let hk = Hkdf::<Sha256>::new(None, kek.as_bytes());
        let mut out = [0u8; KEY_LEN];
        hk.expand(INFO, &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        IndexKey(out)
    }

    /// Tag for one token in one field.
    pub fn tag(&self, field: &str, token: &str) -> [u8; TAG_LEN] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(&(field.len() as u32).to_le_bytes());
        mac.update(field.as_bytes());
        mac.update(token.as_bytes());
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&full[..TAG_LEN]);
        tag
    }

    /// Tags for every token in `text`, deduplicated.
    pub fn tags(&self, field: &str, text: &str) -> Vec<[u8; TAG_LEN]> {
        tokens(text).iter().map(|t| self.tag(field, t)).collect()
    }
}

/// Normalize text into searchable tokens: Unicode-lowercased, split on
/// anything that is not alphanumeric, deduplicated, order preserved.
///
/// `/` and `-` and `_` are separators, so `prod/aws-billing_key` yields
/// `prod`, `aws`, `billing`, `key` and any of them finds the item.
pub fn tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| !c.is_alphanumeric()) {
        if raw.is_empty() {
            continue;
        }
        let t = raw.to_lowercase();
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}
