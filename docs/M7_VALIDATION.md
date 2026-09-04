# M7 Validation — hardening and first signed release

**Milestone:** M7 from [`MASTER_PLAN.md`](MASTER_PLAN.md).
**Gate:** external-review checklist, fuzzing on parsers, signed release,
restore-from-backup drill.
**Status:** all four gate items delivered on 2026-09-04, in `v0.2.0`. What is
still not done is listed at the end, and the most important item there is the
one M7 can never deliver by itself: an actual external review by someone who
did not write this.

## What each gate item produced

| Gate item | Delivered | Where |
| --- | --- | --- |
| External-review checklist | A brief that states the six claims a reviewer should try to break, maps each to code and tests, and lists the eight weaknesses we already know about | [`EXTERNAL_REVIEW.md`](EXTERNAL_REVIEW.md) |
| Fuzzing on parsers | Four `cargo-fuzz` targets over every place the program parses bytes it did not write; 60 s per target on each push that touches them, 15 min weekly | [`fuzz/`](../fuzz), `.github/workflows/fuzz.yml` |
| Signed release | Sigstore keyless signing of `SHA256SUMS`, verified inside the same job before the release is drafted | `.github/workflows/release.yml` |
| Restore-from-backup drill | Both recovery routes exercised end to end through the real binary, including the failures that make a backup worth having | `crates/bsc/tests/restore_drill.rs` |

Plus the dependency policy the review brief needed to be able to claim:
`deny.toml`, checked for licences, bans and sources on every push and for
RustSec advisories daily (`.github/workflows/advisories.yml`).

## The bug fuzzing preparation found, before any fuzzer ran

Writing the bundle target meant reading `open_bundle` as an attacker would,
and the parser had a hole:

> A `.bscx` bundle carries its own Argon2 parameters in the header, because the
> reader has to know how to derive the key. `open_bundle` checked only that
> they were non-zero and that `m_cost_kib >= 8`. **There was no upper bound.**
> A bundle claiming `m_cost_kib = 0xFFFFFFFF` asks Argon2 for four terabytes.
> The tag would have rejected the file a moment later, but the allocation
> happens first.

This is exactly the input a break-glass bundle is designed to be: a file handed
over by somebody else. `bsc import` on a hostile bundle could take the machine
down.

Fixed in `kdf::KdfParams::validate_from_file`, applied both to bundle headers
and to the KDF parameters stored in a vault file. Ceilings: 1 GiB memory,
16 passes, 16 lanes — real files use 64 MiB / 3 / 4. The minimum is deliberately
*not* enforced on read: a vault written by an older or a test build must still
open, and a weak KDF costs its creator, not its reader.

The same read also removed a `Box::leak` that ran once per bundle operation —
harmless in a CLI that opens one bundle, unbounded in a fuzzing loop or a
long-lived process.

Evidence: `crates/bsc-crypto/tests/hostile.rs`, five tests, including one that
asserts the refusal happens in under a second — because failing eventually is
not the same as refusing.

## Evidence — local, macOS, 2026-09-04

```
cargo fmt --check · clippy -D warnings                          ok
cargo test --workspace                                          136 passed
  new in M7: bsc-crypto hostile 5 · bsc restore_drill 4
cargo deny check bans licenses sources                          ok
cargo deny check advisories                                     ok
```

What the restore drill establishes, specifically:

- A copied vault file restores completely: three items, one of them with two
  versions, all values byte-identical, the ledger verifying, after the original
  was deleted.
- `bsc audit` verifies a backup **while it is still sealed**, which is how an
  operator checks a backup without unsealing anything.
- That copy is useless to whoever holds it without the passphrase: unseal
  fails, and neither item names nor values appear anywhere in the file's bytes.
- A break-glass export restores into a *different* vault under a *different*
  passphrase — the successor's case — with new references, the same contents,
  and version history intact.
- A wrong export passphrase is refused three ways, and a failed import leaves
  no rows behind.

Fuzzing has run only in CI, and only for the bounded times above. No crash has
been found; that is a weak statement after minutes of fuzzing, and it is the
honest one.

## Not done — explicitly

- **No external review has happened.** The checklist exists; nobody outside
  this project has used it. Until then, the security claims are self-assessed.
- **The signing chain proves a workflow, not a person.** Keyless Sigstore binds
  the certificate to this repository, this workflow and this tag. It does not
  prove a maintainer approved the release, and anyone who can push a tag can
  produce a valid signature. A hardware-key-backed signature is not planned.
- **v0.1.0's artifacts are not signed** — signing starts at v0.2.0.
- **Fuzzing corpora are not persisted between runs**, so each run starts cold.
  A corpus cache would find more, and is worth doing before claiming coverage.
- **The Web UI has still had no XSS review**, and the dependency tree has had
  no hand audit; `cargo deny` is a policy check, not a reading.
- **The production restore has not been performed by a human**, which is the
  drill that actually matters. What was checked on the host on 2026-09-04: all
  three upgrade-time backups exist and their ledgers verify while sealed —
  25, 42 and 45 records, strictly nested inside the live vault's 49, which is
  what an append-only ledger should look like — and the daily anchor timer is
  enabled with three anchors recorded. Restoring content needs the operator's
  passphrase, so the last step is theirs; the procedure is in the
  [installation manual](manual/en/install.md).
