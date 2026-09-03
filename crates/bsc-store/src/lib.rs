//! Sealed storage for Bastet Secret Chain.
//!
//! A [`Vault`] is a single SQLite file in WAL mode holding encrypted items,
//! their versions, a blind search index, and a hash-chained audit ledger.
//! It opens **sealed**: metadata that is stored in the clear by design (item
//! ids, types, timestamps, sizes) can be listed, the audit chain can be
//! verified, but nothing encrypted is readable until [`Vault::unseal`] derives
//! the KEK from the operator passphrase.
//!
//! Two rules from the ADRs are enforced here rather than by convention:
//!
//! - **No secret leaves without an audit record.** Every read appends to the
//!   ledger *before* decrypting (`docs/adr/0004-hash-chained-audit-ledger.md`).
//! - **Names and paths are ciphertext on disk.** Only the blind index makes
//!   them searchable (`docs/adr/0003-...`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
mod error;
pub mod model;
mod schema;
mod vault;

pub use error::{Result, StoreError};
pub use vault::{Actor, Vault};
