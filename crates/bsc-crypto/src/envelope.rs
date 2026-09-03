//! Envelope encryption for item bodies and direct encryption for small fields.
//!
//! Every ciphertext binds an [`Aad`] — the format tag, item id, version, and
//! field name — as AEAD associated data. Moving a ciphertext to another item,
//! another version, or another column fails authentication.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

use crate::{fill_random, kdf::Kek, CryptoError, Result, FORMAT, KEY_LEN, NONCE_LEN, TAG_LEN};

/// Identity bound into a ciphertext. Two ciphertexts with different `Aad`
/// values are never interchangeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aad<'a> {
    /// Opaque item id. Empty for vault-level records.
    pub item_id: &'a str,
    /// Version number. Zero for non-versioned fields.
    pub version: u32,
    /// Which field this ciphertext belongs to: `"body"`, `"name"`, `"path"`, …
    pub field: &'a str,
}

impl Aad<'_> {
    /// Canonical byte encoding. Length-prefixed so `("ab","c")` and
    /// `("a","bc")` cannot collide.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(FORMAT.len() + self.item_id.len() + self.field.len() + 4 * 4 + 4);
        push_field(&mut out, FORMAT.as_bytes());
        push_field(&mut out, self.item_id.as_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        push_field(&mut out, self.field.as_bytes());
        out
    }
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// An XChaCha20-Poly1305 ciphertext with its nonce. Serializes as
/// `nonce || ciphertext || tag` so it can be stored as a single blob.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    nonce: [u8; NONCE_LEN],
    ct: Vec<u8>,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed")
            .field("len", &self.ct.len())
            .finish_non_exhaustive()
    }
}

impl Sealed {
    /// Serialize to a single blob.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ct.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse a blob produced by [`Sealed::to_vec`].
    pub fn from_slice(bytes: &[u8]) -> Result<Sealed> {
        if bytes.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Encoding);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);
        Ok(Sealed {
            nonce,
            ct: bytes[NONCE_LEN..].to_vec(),
        })
    }

    /// Plaintext length this ciphertext will decrypt to.
    pub fn plaintext_len(&self) -> usize {
        self.ct.len() - TAG_LEN
    }
}

/// A data-encryption key wrapped under the KEK. Opaque bytes; store as-is.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedDek(Vec<u8>);

impl fmt::Debug for WrappedDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrappedDek(<opaque>)")
    }
}

impl WrappedDek {
    /// Raw bytes for storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Reconstruct from storage.
    pub fn from_bytes(bytes: Vec<u8>) -> WrappedDek {
        WrappedDek(bytes)
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct Dek([u8; KEY_LEN]);

fn encrypt(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Sealed { nonce, ct })
}

fn decrypt(key: &[u8; KEY_LEN], aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// Encrypt an item body under a fresh data key, and wrap that key under the
/// KEK. Both the wrap and the body bind the same `aad`, with the field name
/// suffixed so the two ciphertexts are never confusable.
pub fn seal_body(kek: &Kek, aad: &Aad<'_>, plaintext: &[u8]) -> Result<(WrappedDek, Sealed)> {
    let mut dek = Dek([0u8; KEY_LEN]);
    fill_random(&mut dek.0)?;

    let body = encrypt(&dek.0, &aad.to_bytes(), plaintext)?;
    let wrap_aad = Aad {
        field: &format!("{}/dek", aad.field),
        ..*aad
    };
    let wrapped = encrypt(kek.as_bytes(), &wrap_aad.to_bytes(), &dek.0)?;
    Ok((WrappedDek(wrapped.to_vec()), body))
}

/// Unwrap the data key and decrypt the body. Any mismatch — key, item,
/// version, field, or a modified byte — is a single opaque failure.
pub fn open_body(
    kek: &Kek,
    aad: &Aad<'_>,
    wrapped: &WrappedDek,
    body: &Sealed,
) -> Result<Zeroizing<Vec<u8>>> {
    let wrap_aad = Aad {
        field: &format!("{}/dek", aad.field),
        ..*aad
    };
    let wrapped_sealed = Sealed::from_slice(&wrapped.0)?;
    let dek_bytes = decrypt(kek.as_bytes(), &wrap_aad.to_bytes(), &wrapped_sealed)?;
    if dek_bytes.len() != KEY_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut dek = Dek([0u8; KEY_LEN]);
    dek.0.copy_from_slice(&dek_bytes);
    decrypt(&dek.0, &aad.to_bytes(), body)
}

/// Re-wrap a version's data key under a new KEK without touching the body.
/// The wrap binds the same identity (`aad` with the `/dek` suffix), so a
/// rewrapped key still only opens its own item and version.
pub fn rewrap_dek(
    old_kek: &Kek,
    new_kek: &Kek,
    aad: &Aad<'_>,
    wrapped: &WrappedDek,
) -> Result<WrappedDek> {
    let wrap_aad = Aad {
        field: &format!("{}/dek", aad.field),
        ..*aad
    };
    let sealed = Sealed::from_slice(&wrapped.0)?;
    let dek_bytes = decrypt(old_kek.as_bytes(), &wrap_aad.to_bytes(), &sealed)?;
    if dek_bytes.len() != KEY_LEN {
        return Err(CryptoError::Decrypt);
    }
    let rewrapped = encrypt(new_kek.as_bytes(), &wrap_aad.to_bytes(), &dek_bytes)?;
    Ok(WrappedDek(rewrapped.to_vec()))
}

/// Encrypt a small metadata field (name, path, tag, note) directly under the
/// KEK. No per-field data key: rotating the passphrase re-encrypts these,
/// which is cheap because they are small.
pub fn seal_field(kek: &Kek, aad: &Aad<'_>, plaintext: &[u8]) -> Result<Sealed> {
    encrypt(kek.as_bytes(), &aad.to_bytes(), plaintext)
}

/// Decrypt a field sealed with [`seal_field`].
pub fn open_field(kek: &Kek, aad: &Aad<'_>, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    decrypt(kek.as_bytes(), &aad.to_bytes(), sealed)
}

const VERIFIER_PLAINTEXT: &[u8] = b"bsc-verifier/1";
const VERIFIER_AAD: Aad<'static> = Aad {
    item_id: "",
    version: 0,
    field: "verifier",
};

/// Produce the vault-header verifier: a known constant sealed under the KEK.
/// Lets the store reject a wrong passphrase immediately instead of failing
/// on the first item read.
pub fn make_verifier(kek: &Kek) -> Result<Sealed> {
    seal_field(kek, &VERIFIER_AAD, VERIFIER_PLAINTEXT)
}

/// Check a candidate KEK against the stored verifier. Constant-time on the
/// plaintext comparison; the AEAD tag check already dominates.
pub fn check_verifier(kek: &Kek, verifier: &Sealed) -> bool {
    match open_field(kek, &VERIFIER_AAD, verifier) {
        Ok(pt) => {
            use subtle::ConstantTimeEq;
            pt.len() == VERIFIER_PLAINTEXT.len() && pt.ct_eq(VERIFIER_PLAINTEXT).into()
        }
        Err(_) => false,
    }
}
