# M1 Validation — crypto core and sealed storage

**Milestone:** M1 from [`MASTER_PLAN.md`](MASTER_PLAN.md) §6.
**Gate text:** Argon2id/XChaCha20 envelope, SQLite WAL schema, seal/unseal,
zeroization; property tests + known-answer vectors.
**Status:** delivered locally on 2026-09-03; three-platform CI evidence is
recorded below as it arrives. Nothing here is a release.

## What was built

| Crate | Purpose | Key types |
| --- | --- | --- |
| `bsc-crypto` | Argon2id KDF, envelope encryption, blind index | `KdfParams`, `Kek`, `Aad`, `Sealed`, `WrappedDek`, `IndexKey` |
| `bsc-store` | SQLite WAL vault, versions, search, hash-chained ledger | `Vault`, `Actor`, `NewItem`, `ItemMeta`, `ItemDetail`, `AuditRecord`, `ChainStatus` |

Both crates are `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

### How the ADRs show up in code

- **ADR 0003** — `Kek::derive` is Argon2id v1.3 with parameters stored in the
  vault `meta` table; production default 64 MiB / 3 passes / 4 lanes,
  minimum 8 MiB enforced by `KdfParams::new`. `envelope::seal_body` creates a
  fresh random DEK per version, wraps it under the KEK, and binds
  `(format, item_id, version, field)` as AEAD associated data on both the
  body and the wrap, with distinct field labels so the two ciphertexts cannot
  be swapped. Item `path`, `name`, and `tags` are encrypted with
  `seal_field`; `IndexKey::derive` produces the HKDF-derived blind-index key.
- **ADR 0004** — `audit::append` writes a SHA-256 record chained to its
  predecessor with length-prefixed fields; `audit::verify` recomputes the
  whole chain. `Vault::read_version` appends the `secret_read` record
  **before** decrypting and rolls back to an `error` record if decryption
  fails, so the ledger never claims a release that did not happen. Sealed-vault
  read attempts and rejected passphrases are recorded as `denied`.
- **ADR 0005 §1 tiering** — `ItemType::approval_required_by_default` is true
  for `ServiceAccount`, `CloudKey`, `Certificate` and is honored by
  `Vault::put` unless explicitly overridden.
- **Zeroization** — `Kek`, `IndexKey`, and the internal `Dek` are
  `#[zeroize(drop)]`; every decrypted buffer is returned as
  `Zeroizing<Vec<u8>>`; no secret-bearing type prints its contents in `Debug`.
- **Decryption failures are one opaque error** (`CryptoError::Decrypt`) so the
  API is not an oracle for wrong-key vs tampered vs wrong-AAD.

## Evidence — local, macOS, 2026-09-03

```
cargo fmt --all -- --check                                   ok
cargo clippy --workspace --all-targets -- -D warnings         ok (0 warnings)
cargo test --workspace                                        43 passed, 0 failed
  bsc-crypto  tests/properties.rs   19   (proptest, 256 cases each)
  bsc-crypto  tests/vectors.rs       4   (known-answer)
  bsc-store   tests/audit_chain.rs   7
  bsc-store   tests/vault.rs        13
```

### What the property tests establish

Round-trip for bodies and fields over arbitrary bytes and AADs; a wrong KEK,
a different item id, a different version, any flipped bit in the body, and any
flipped bit in the wrapped DEK all fail with `Decrypt`; body and wrap
ciphertexts of equal length are not interchangeable; every seal uses a fresh
nonce; the AAD encoding is injective; blind-index tags are field-scoped and
KEK-scoped; tokenization is lowercase, unique, and non-empty.

### What the known-answer vectors pin

The AAD byte encoding, two blind-index tags (which pins Argon2id → HKDF →
HMAC end to end for the test parameters), and one body plus one field
ciphertext generated once by `examples/gen_vectors.rs` that must keep
decrypting. Changing any of these is a format change. CI re-runs the
generator and checks the deterministic lines match.

### What the store tests establish

A fresh vault is created unsealed and reopens sealed with `0600` permissions
on Unix; names, paths, tags, and bodies do not appear in the vault file
(including WAL/SHM); versions append and old versions stay readable; a sealed
vault lists metadata but refuses reads, details, and search, and records the
refusal; right and wrong passphrases both leave ledger records; search is
exact-token with AND semantics across name, path, and tags; reads record
actor and reason before release; and the ledger detects a field edit, an edit
with a recomputed hash, and a deleted middle record. One test documents the
known residual: **tail truncation verifies clean** until the head hash is
anchored outside the vault (ADR 0004, scheduled for M6).

## Not done — explicitly

- No daemon, HTTP API, MCP server, tokens, approvals, sessions, or UI. Those
  are M2–M3; the contract they must satisfy is
  [`API_CONTRACT.md`](API_CONTRACT.md).
- No passphrase rotation (rewrap DEKs under a new KEK). The data model
  supports it; the operation is not written.
- No OS-keychain unattended unseal. The `Vault` API takes a passphrase only.
- No item deletion or metadata edit. Append-only for now.
- No auto-reseal timer. Sealing is explicit.
- **Dependency versions** were pinned to the RustCrypto 0.10/0.12 series
  (`sha2 0.10`, `hmac 0.12`, `hkdf 0.12`, `chacha20poly1305 0.10`,
  `argon2 0.5`) rather than the 0.11/0.13 series that is current on crates.io,
  because those APIs are the ones this code was reviewed against. Upgrading is
  an M7 hardening task, and the KAT vectors are what makes that upgrade safe.
- `getrandom` failure is surfaced as `CryptoError::Randomness` and is
  untested, because it cannot be provoked on a healthy host.
- Zeroization is asserted structurally (types), not by inspecting memory.

## CI evidence

| Run | Ubuntu | macOS | Windows | Hygiene |
| --- | --- | --- | --- | --- |
| _pending first push_ | — | — | — | — |
