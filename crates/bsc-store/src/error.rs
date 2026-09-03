use thiserror::Error;

/// Errors from the store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Operation needs an unsealed vault.
    #[error("vault is sealed")]
    Sealed,
    /// Passphrase did not verify.
    #[error("passphrase rejected")]
    BadPassphrase,
    /// No such item.
    #[error("item not found")]
    NotFound,
    /// The file exists but is not a vault this version understands.
    #[error("not a vault or unsupported format: {0}")]
    Format(String),
    /// The audit chain failed verification at the given record.
    #[error("audit chain broken at record {0}")]
    ChainBroken(u64),
    /// Cryptographic failure.
    #[error(transparent)]
    Crypto(#[from] bsc_crypto::CryptoError),
    /// Database failure.
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    /// Filesystem failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Bad caller input.
    #[error("invalid input: {0}")]
    Invalid(&'static str),
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, StoreError>;
