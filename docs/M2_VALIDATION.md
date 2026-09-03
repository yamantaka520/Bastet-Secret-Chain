# M2 Validation — daemon API, tokens, approvals, audit, MCP

**Milestone:** M2 from [`MASTER_PLAN.md`](MASTER_PLAN.md) §6.
**Gate text:** versioned API, scoped tokens, renewal, task sessions,
pending-approval protocol, structured agent errors, hash-chain ledger with a
verifier, `bsc mcp` server; chain-tamper detection test and an agent-facing
error-contract test.
**Status:** gate met locally on 2026-09-03; CI evidence is recorded below.
Nothing here is a release, and nothing here is a UI.

## What was built

| Crate | Purpose |
| --- | --- |
| `bsc-store` (extended) | `access` module: tokens (hash-only storage, encrypted label and scope), task sessions, approvals with escalation state, trust-on-first-use grants; `local_approval_only` flag; injectable clock; `verify_passphrase` |
| `bsc-daemon` | axum `/v1` router with the agent and human surfaces, the error contract, same-origin discipline, rate limiting, the approval ticker, a `Notifier` seam |
| `bsc-mcp` | JSON-RPC 2.0 stdio MCP server: five read-only tools, forwards to the daemon, returns its JSON verbatim |
| `bsc` | the binary: `init`, `serve`, `mcp`, `audit` |

### How the ADRs and the contract show up in code

- **ADR 0002** — an item's id *is* its `sref`, 128 random bits, and appears in
  URLs freely. Nothing in `bsc-daemon` releases a value without a `bsct_`
  token in the `Authorization` header; `sref` alone reaches `unauthorized`.
  Handoff links return `handoff_disabled` because the feature is off.
- **ADR 0004** — the daemon never bypasses `Vault::read_version`, so the
  `secret_read` record still precedes decryption. Human `/reveal` is a
  `secret_read` too. `GET /v1/audit/verify` and `bsc audit` recompute the
  chain; `bsc audit` exits non-zero on a break.
- **ADR 0005** — `Config` carries the §6 defaults (5-minute approval wait,
  0/20/60 s ladder, 30-minute grant, 30-minute session default, 8-hour session
  cap). A blocked read returns `202 approval_pending` with `Retry-After` and
  `Location`, not `403`. `AppState::tick` times out overdue approvals and
  records each ladder step once as `approval_escalated`, then hands it to the
  `Notifier` (a `tracing` sink in M2; OS notifications are M3). Sessions never
  renew; grants are capped at token expiry.
- **ADR 0006** — `bsc-mcp` holds one token and forwards five tools. There is
  no write tool. `get_secret`'s description carries the live-secret warning and
  the no-paste instruction; `initialize` returns the same as server
  `instructions`. The reason travels in `X-BSC-Reason`, never the URL.
  Every tool result is the daemon's body verbatim (`structuredContent`) plus
  the same JSON as text, `isError` true for 4xx/5xx and **false** for `202`.
- **Error contract** — `error::ApiError` is the §4 table: fourteen agent codes
  plus `unauthorized`, three human codes, and `internal`. Each carries
  `message`, `next_action`, `do_not`, `request_id`; the value-releasing codes'
  `do_not` all forbid asking for a paste. Unknown routes and malformed JSON
  speak the same shape.
- **Same-origin** — the human surface needs `SameSite=Strict; HttpOnly`
  cookie *and* an `X-BSC-Client` header on writes, and refuses any foreign
  `Origin`. A `bsct_` token never grants the human surface.
- **Loopback** — `bsc serve` refuses a non-loopback `--bind` before opening
  the socket.

## Evidence — local, macOS, 2026-09-03

```
cargo fmt --all -- --check                                   ok
cargo clippy --workspace --all-targets -- -D warnings         ok (0 warnings)
cargo test --workspace                                        79 passed, 0 failed
  bsc-crypto  properties 19 · vectors 4
  bsc-store   access 14 · audit_chain 7 · vault 13
  bsc-daemon  api 12
  bsc-mcp     parity 5
  bsc         cli 5
```

### The two gate tests

**`bsc-daemon/tests/api.rs::error_contract_every_code_reachable_with_shape_and_status`**
provokes, over a real socket with a fixed clock, every agent code in the
contract table — `unauthorized`, `token_revoked`, `scope_mismatch`,
`approval_pending` (202 with `Retry-After` and `Location`), `approval_denied`,
`approval_timeout`, `quota_exhausted`, `rate_limited`, `not_found`,
`reason_required`, `invalid_request`, `handoff_disabled`, `token_expired`
(renewable), `vault_sealed` — asserts status and shape for each, asserts that
every value-releasing code's `do_not` mentions pasting, and fails if any code
in the list was not exercised.

**`bsc-mcp/tests/parity.rs::mcp_and_http_return_identical_json_for_success_and_every_reachable_error`**
runs the daemon in-process and asserts the MCP `structuredContent` equals the
HTTP body (minus `request_id`) for a successful read, a listing,
`reason_required`, `not_found`, `approval_pending` (the same pending request
from both doors), `token_expired`, and `vault_sealed`; then walks
pending → approved → value once → `consumed`, and renews through MCP.

### What the other tests establish

Login sets the cookie and a wrong passphrase is a `login denied` ledger record;
cookie, client header, and origin are each enforced; a token never reaches the
human surface; agent reads carry `Cache-Control: no-store`,
`X-BSC-Token-Expires-In`, `X-BSC-Reads-Remaining`, and land in the ledger with
token actor and verbatim reason while neither value nor token value appears
anywhere in it; listing is scoped and filtered and value-free; the approval
flow — pending, deduplicated re-request, inbox with verbatim reason and
labels, immediate notification, approve, value once, consumed, grant, grant
expiry; denial, three-step escalation, timeout, and refusal to decide after
timeout; a task session suppresses the prompt inside its scope and lapses
without renewal; the renewal window opens at the final quarter, the warning
appears at 20 %, an expired token inside grace renews, and past grace it is
dead; sealing drops human sessions and gives agents `503`; reveal demands the
passphrase only for approval-required items; versions, binary values, and
`PATCH` flags work. On the store side: scope matching on segment boundaries,
hash-only token storage with encrypted label, renewal math and the lifetime
cap, idempotent revoke, quota countdown, session bounds, approval lifecycle,
grant cap at token expiry, escalation ladder and timeout records. The binary:
help, offline audit intact and broken, non-loopback refusal, MCP token
validation.

## Not done — explicitly

- **No UI.** Every human operation is an HTTP call. M3.
- **No OS notifications and no external channel.** `Notifier` is a `tracing`
  sink. Ladder steps are recorded and delivered to the seam, not to a human.
  M3 / M6.
- **No `use_secret` / `bsc exec`.** Values still reach the agent. M6.
- **No handoff links.** The route exists only to return `handoff_disabled`.
- **No passphrase rotation, keychain unseal, item deletion, auto-reseal.**
  Unchanged from M1.
- **Rate limiting is per process and in memory.** A restart forgets the
  window. Acceptable for a single-operator loopback daemon; noted.
- **Human sessions are in memory.** A restart logs everyone out. Intended.
- **`bsc init` is untested end to end** because it prompts on a TTY; the
  vault creation it wraps is covered in `bsc-store`.
- **`bsc serve` has no reboot or auto-start story.** M4.
- The schema gained tables without a version bump. Pre-release only; from the
  first tag every change migrates.
- Dependency series unchanged from M1 (RustCrypto 0.10/0.12, axum 0.7,
  reqwest 0.12). M7.

## CI evidence

| Run | Commit | Ubuntu | macOS | Windows | Hygiene |
| --- | --- | --- | --- | --- | --- |
| _pending_ | — | — | — | — | — |
