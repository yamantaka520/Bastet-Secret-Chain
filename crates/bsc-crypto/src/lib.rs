//! Cryptographic core for Bastet Secret Chain.
//!
//! This crate owns every primitive that touches key material or plaintext:
//!
//! - [`kdf`] derives the key-encryption key (KEK) from the operator passphrase
//!   with Argon2id, using parameters stored alongside the vault so they can be
//!   raised later without a format change.
//! - [`envelope`] encrypts item bodies under a fresh per-version data key (DEK)
//!   wrapped by the KEK, and encrypts small metadata fields directly under the
//!   KEK. Both bind the item identity into the AEAD associated data, so a
//!   ciphertext cannot be replayed under a different item or version.
//! - [`blind_index`] derives a separate index key from the KEK and produces
//!   keyed token hashes, so encrypted names can be searched by exact token
//!   without revealing the names on disk.
//!
//! Design authority: `docs/adr/0003-envelope-encryption-with-argon2id-and-xchacha20.md`.
//!
//! Everything holding key material or plaintext is a zeroizing type, and no
//! secret-bearing type implements `Debug` in a way that prints its contents.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod blind_index;
pub mod envelope;
mod error;
pub mod kdf;

pub use error::{CryptoError, Result};

/// Format tag bound into every associated-data string. Bump only with a
/// migration path; a mismatch makes every existing ciphertext undecryptable.
pub const FORMAT: &str = "bsc/1";

/// Length in bytes of every symmetric key this crate handles.
pub const KEY_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

/// Fill `buf` with operating-system randomness. Failure is unrecoverable for a
/// vault, so it is surfaced as an error rather than papered over.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| CryptoError::Randomness)
}
