# ADR 0003 — Envelope encryption with Argon2id and XChaCha20-Poly1305

- **Status:** accepted, 2026-09-03
- **Deciders:** project owner

## Context

The vault stores long-lived, high-value credentials on a laptop that may be
lost, backed up to third-party storage, or synced to a cloud folder. The file
must be useless without the operator's passphrase, and changing the passphrase
must not require re-encrypting every item.

## Decision

- **Argon2id** derives a 32-byte key-encryption key from the passphrase, with
  parameters stored in the vault header so they can be raised without a format
  change.
- **Envelope encryption:** each item version gets a fresh random data key,
  wrapped by the KEK. Passphrase rotation rewraps data keys only.
- **XChaCha20-Poly1305** for all item encryption, random 24-byte nonce per
  operation, with the item id and version number bound in as associated data so
  a ciphertext cannot be replayed under another identity.
- **Item names and paths are encrypted**, with a keyed blind index over
  lowercase name tokens providing search. Type, size, and timestamps stay clear
  so the UI can render a sealed vault's shape.
- All key material and plaintext buffers use zeroizing types.

## Consequences

- A stolen vault file resists offline attack in proportion to the passphrase and
  the Argon2id parameters.
- Rotation is cheap; re-encryption is not needed on passphrase change.
- Search is exact-token only against the blind index; substring and fuzzy search
  require an unsealed vault. Accepted.
- Clear metadata leaks activity patterns and vault size. Recorded as a residual
  risk in the threat model rather than silently ignored.
