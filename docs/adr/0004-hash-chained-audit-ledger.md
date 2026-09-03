# ADR 0004 — A hash-chained, append-only audit ledger

- **Status:** accepted, 2026-09-03
- **Deciders:** project owner

## Context

The primary consumer of this vault is automated. Agents will read secrets
without a human watching, and the realistic failure mode is not a broken cipher
but an agent — possibly one manipulated by hostile input — using legitimate
authority in an illegitimate way. When that happens, the only thing that helps
is an accurate, complete, hard-to-edit record of what was taken.

## Decision

Every read, write, seal, unseal, token mint, token revoke, approval decision,
and network-exposure acknowledgement appends a record to a ledger where record
*n* commits to the hash of record *n-1*. `bsc audit verify` recomputes the chain
and reports the first divergence. Records are never updated or deleted; a
correction is a new record that references the earlier one.

## Consequences

- Editing or removing history is detectable, which gives the "Chain" in the
  project's name its literal meaning.
- Truncating the tail is only detectable if the head hash is anchored outside
  the vault. Periodic anchoring is deferred to M6 and recorded as a known gap.
- The ledger grows without bound; compaction must preserve chain continuity
  through checkpoint records rather than deletion.
- No code path may return a secret without appending a record first. This is a
  review gate at every milestone, not merely a convention.
