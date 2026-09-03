use thiserror::Error;

/// Errors from the cryptographic core.
///
/// Decryption failures are deliberately a single variant. Distinguishing
/// "wrong key" from "tampered ciphertext" from "wrong associated data" would
/// hand an attacker an oracle for free and buys the operator nothing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// The KDF rejected its parameters or failed internally.
    #[error("key derivation failed")]
    Kdf,
    /// Authenticated decryption failed: wrong key, wrong associated data, or
    /// modified ciphertext.
    #[error("decryption failed")]
    Decrypt,
    /// The operating system could not supply randomness.
    #[error("operating system randomness unavailable")]
    Randomness,
    /// A serialized blob was too short or otherwise malformed.
    #[error("malformed ciphertext encoding")]
    Encoding,
    /// A parameter was outside the range this crate is willing to use.
    #[error("parameter out of range: {0}")]
    Parameter(&'static str),
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, CryptoError>;
