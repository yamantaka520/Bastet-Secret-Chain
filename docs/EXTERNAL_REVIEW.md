# External review brief

**For:** a security reviewer who has never seen this code.
**Version:** 0.2.0 (`v0.2.0`), which is 0.1.0 plus the M7 hardening pass.
**Time budget this brief assumes:** one focused day for the crypto and the
release path, three days for everything.

The point of this document is to make a reviewer's first two hours productive
instead of archaeological: what the system claims, where the claims live in the
code, what is already tested, and what we already know is weak.

---

## 1. What the system claims

1. **A reference URL releases nothing.** Possession of `sref_…`, in any log,
   ticket, transcript or proxy record, gives no access. Only a live `bsct_…`
   token in an `Authorization` header does, and only inside its scope.
   ([ADR 0002](adr/0002-reference-urls-are-not-credentials.md))
2. **At rest, a sealed vault reveals no secret and no name.** Values, item
   names, paths, tags, use bindings, token labels and session scopes are all
   ciphertext. What a sealed vault does reveal, deliberately: item count, types,
   environment labels, timestamps, expiry, and the whole audit ledger.
3. **A read cannot happen without a record.** Every release, mint, revoke,
   approval and deletion is appended to a hash-chained ledger before the value
   reaches the caller.
4. **A high-value read cannot happen without a human**, unless a human
   previously granted that exact token that exact item, or opened a task
   session covering it.
5. **The daemon never hands a secret to a browser origin it was not told
   about**, and never listens anywhere but loopback unless an operator passed
   `--public-origin`.
6. **An agent that follows its tool descriptions never asks a human to paste a
   credential.** This is a design claim about text, not about code, and it is
   the one most worth attacking.

A finding is anything that breaks one of these six, or that makes a false one
look true.

---

## 2. Where to look

| Claim | Code | Tests |
| --- | --- | --- |
| Envelope encryption, KDF | `crates/bsc-crypto/src/{kdf,envelope}.rs` | `tests/properties.rs`, `tests/vectors.rs` (known-answer, regenerated in CI) |
| Bundle format, untrusted input | `crates/bsc-crypto/src/bundle.rs` | `tests/hostile.rs` |
| Blind index (searchable encrypted names) | `crates/bsc-crypto/src/blind_index.rs` | `tests/properties.rs` |
| Vault lifecycle, seal/unseal, migrations | `crates/bsc-store/src/vault.rs`, `schema.rs` | `tests/vault.rs`, `tests/migrate.rs` |
| Tokens, scope, quota, renewal, approvals, grants | `crates/bsc-store/src/access.rs` | `tests/access.rs`, `tests/lifecycle.rs` |
| Ledger and anchoring | `crates/bsc-store/src/audit.rs` | `tests/audit_chain.rs` |
| Agent HTTP surface | `crates/bsc-daemon/src/agent.rs` | `tests/api.rs` |
| Human surface, origin and cookie rules | `crates/bsc-daemon/src/{human,auth}.rs` | `tests/api.rs`, `tests/exposure.rs` |
| Use-without-seeing, SSRF guard | `crates/bsc-daemon/src/use_secret.rs` | `tests/use_secret.rs` |
| External approval channel | `crates/bsc-daemon/src/telegram.rs` | `tests/telegram.rs` |
| Error contract and `do_not` text | `crates/bsc-daemon/src/error.rs`, [`API_CONTRACT.md`](API_CONTRACT.md) | `tests/api.rs`, `crates/bsc-mcp/tests/parity.rs` |
| Unattended unseal | `crates/bsc/src/main.rs` | `tests/unattended.rs` |

Design records worth reading before the code: [`MASTER_PLAN.md`](MASTER_PLAN.md)
§1–3, [`THREAT_MODEL.md`](THREAT_MODEL.md) in full, and ADRs
[0002](adr/0002-reference-urls-are-not-credentials.md),
[0003](adr/0003-envelope-encryption-with-argon2id-and-xchacha20.md),
[0005](adr/0005-approval-and-reminder-model.md).

---

## 3. Build and run it in five minutes

```sh
npm --prefix ui ci && npm --prefix ui run build
cargo test --workspace                     # 136 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p bsc-crypto --example gen_vectors | diff - crates/bsc-crypto/tests/vectors.txt

cargo run -p bsc -- init --vault /tmp/rv.bsc
cargo run -p bsc -- serve --vault /tmp/rv.bsc --bind 127.0.0.1:8799
```

Fuzzing (nightly toolchain):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run bundle -- -max_total_time=300
cargo +nightly fuzz list          # every target
```

---

## 4. Questions we would most like answered

Ordered by how much a wrong answer would cost.

1. **Is the AAD binding actually total?** Every ciphertext binds
   `(format, item_id, version, field)`. Can a ciphertext be moved between two
   items, two versions, or two fields — for example a token's `scope_ct` into
   an item's `name_ct`, or version 2's body into version 3 — and still open?
   See `envelope::Aad::to_bytes` (length-prefixed encoding) and `rewrap_dek`.
2. **Does passphrase rotation leave anything behind?** `rotate_passphrase`
   rewraps every DEK, re-encrypts every KEK-direct field, and rebuilds the
   blind index in one transaction. Is there a field it forgets, a row it
   leaves under the old KEK, or a crash point that leaves the vault
   half-rotated and openable by the old passphrase?
3. **Can the blind index be inverted?** Tags are `HMAC(HKDF(KEK), term)`.
   Given a vault file and a guess at the naming convention, how much of the
   hierarchy can be recovered by a dictionary attack, and does the index leak
   through row counts even without the key?
4. **Is the approval bypassable by timing?** `request_approval` deduplicates
   pending requests, `decide_approval` issues a grant, `consume_approval`
   releases a value once. Two agents racing on one item, an approval decided
   as it times out, a grant revoked mid-read — does any interleaving release a
   value that a human refused?
5. **Does the SSRF guard hold?** `use_secret` resolves the host to check it,
   then the HTTP client resolves it again. DNS rebinding in that window is a
   known and recorded gap; is there a cheaper bypass — redirects, IPv6
   literals, `0.0.0.0`, decimal IPs, userinfo in the URL?
6. **Is the exposure path honest?** With `--public-origin` set, are cookies,
   `Origin` checks, forwarded-address parsing and login throttling all
   consistent? `client_addr` trusts the first `X-Forwarded-For` hop only when
   exposed — is that the right hop for the reference nginx config?
7. **Do the error strings mislead a model?** Read `error.rs` and the tool
   descriptions in `crates/bsc-mcp/src/lib.rs` as an adversary would: is there
   a state where the most natural next action for an LLM is to ask a human to
   paste a credential, or to fall back to an environment variable?

---

## 5. What we already know is weak

These are recorded, not hidden. Confirming them is not a finding; finding them
worse than described is.

- **Unattended unseal means root can unseal.** With no TPM, the systemd
  credential is bound to a root-readable key. Off by default.
- **A live human session on the operator's machine is out of scope**, as is a
  compromised host OS. See [`THREAT_MODEL.md`](THREAT_MODEL.md) §out-of-scope.
- **The ledger is only tamper-*evident*, and only against edits.** A vault
  owner can truncate the tail; anchors outside the vault are the mitigation
  and they are optional. ([ADR 0004](adr/0004-hash-chained-audit-ledger.md))
- **`use_secret` re-resolves DNS.** Rebinding window, documented.
- **Approval defaults are chosen, not measured** — 0/20/60 s and a five-minute
  auto-deny come from ADR 0005 §6 reasoning, with no field data behind them.
- **Release binaries are unsigned at 0.1.0.** From 0.2.0 the checksum file is
  signed with Sigstore keyless signing, which binds the workflow, repository
  and tag — but not a maintainer identity, because there is no project key.
- **No dependency has been audited by hand.** `cargo deny` runs in CI for
  licences, bans and sources, and daily for RustSec advisories; that is not the
  same thing as reading the code.
- **Two versions of `sha2`, `digest` and `crypto-common` are in the tree**
  (transitively, via different RustCrypto generations). `cargo deny` warns
  rather than fails on this; whether it matters is a question for the reviewer.
- **The Web UI has had no XSS review.** It renders values the operator pasted;
  CSP is set in `ui.rs` and has not been attacked.

---

## 6. How to report

Privately, through GitHub Security Advisories on the repository, per
[`SECURITY.md`](../SECURITY.md). Please do not include real credentials or a
real vault file — a redacted reproduction has always been enough.

A finding that says "claim 3 fails because …" with a failing test is worth more
to this project than a long report, and will be credited in the release notes
that fix it.
