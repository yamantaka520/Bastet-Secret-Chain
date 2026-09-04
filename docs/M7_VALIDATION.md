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

### What the fuzzing actually covered

First green run, 60 s per target on an Actions runner (the first attempt failed
outright: `rust-toolchain.toml` pins stable for the repository and overrode the
nightly the workflow installed, so nothing built — worth stating, because a
fuzz job that fails to build looks much like one that finds nothing):

| Target | Executions | Coverage | Corpus | Crashes |
| --- | --- | --- | --- | --- |
| `sealed` | 42.7 M | 23 edges | 2 | none |
| `bundle` | 41.2 M | 34 edges | 3 | none |
| `anchor_line` | 2.7 M | 1181 edges | 2677 | none |
| `export_json` | 11.2 M | 1800 edges | 2502 | none |

Read those numbers honestly. `sealed` and `bundle` execute enormously fast and
explore almost nothing, because both formats are authenticated: without the
key, a mutated byte string fails the tag and the fuzzer never reaches the code
behind it. What they do test is the part that runs *before* authentication —
length checks, the magic, the header decode, the KDF parameter ceiling — which
is exactly where the bug above lived, and exactly the code an attacker reaches
without a key.

The two JSON targets explore properly (thousands of corpus entries, four-figure
coverage) and they are the ones that matter for what runs *after*
authentication: `export_json` is the document a decrypted bundle produces, and
`anchor_line` is a file that lives outside the vault by design.

No crash has been found. After a minute per target that is a weak statement,
and it is the honest one; the weekly run is 15 minutes and starts cold, which
is the next thing worth fixing.

## Not done — explicitly

- **No external review has happened.** The checklist exists; nobody outside
  this project has used it. Until then, the security claims are self-assessed.
- **The signing chain proves a workflow, not a person.** Keyless Sigstore binds
  the certificate to this repository, this workflow and this tag. It does not
  prove a maintainer approved the release, and anyone who can push a tag can
  produce a valid signature. A hardware-key-backed signature is not planned.
- **v0.1.0's artifacts are not signed** — signing starts at v0.2.0.
- **Fuzzing corpora are not persisted between runs**, so each run starts cold —
  including the weekly one, which therefore spends its first minutes
  rediscovering what the last run already knew. A corpus cache is the single
  highest-value improvement here.
- **The authenticated formats are barely explored** (23 and 34 edges): fuzzing
  cannot get past an AEAD tag without the key. Fuzzing the post-decryption path
  properly would need a harness that seals its own input, which does not exist.
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
