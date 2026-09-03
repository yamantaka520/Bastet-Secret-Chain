# Bastet Secret Chain — Master Plan

**Status:** M0–M6 delivered; released as `v0.1.0` on 2026-09-04. M7 (hardening,
signed binaries, dependency refresh, external review) not started. Per-milestone
evidence and gaps live in the `M*_VALIDATION.md` files.
**Authority:** this file is the single authority for scope, architecture,
milestones, and gates. Any other document that disagrees with it is stale.

## 1. Purpose

Bastet Secret Chain (BSC) is a **local-first, self-hosted vault for sensitive
credentials** whose primary consumer is **AI agents fetching a secret at the
moment they need it during a task**.

Humans put secrets in through a Web UI. Agents take secrets out through an
authenticated HTTP reference, one item at a time, and every retrieval is
appended to a tamper-evident chain.

### 1.1 In scope

Credential classes the vault must store as first-class item types:

| Type | Examples |
| --- | --- |
| 🔐 Login | account/password pairs, TOTP seeds |
| 🔑 API key | provider API keys, webhook signing secrets |
| ☁️ Cloud key | AWS access key + secret, GCP keys, Azure principals |
| 🔥 Service account | Google/Firebase Admin SDK JSON, deploy credentials |
| 🎫 OAuth | client id/secret, refresh tokens, `client_secret*.json` |
| 🖥️ SSH | private/public keys, passphrases, known-host pins |
| 📜 Certificate | TLS keys and chains, signing certificates, `.p12`/`.jks` |
| 🗂️ File | any other credential-bearing blob |

Also in scope: hierarchical classification, versioning and rotation history,
expiry tracking, agent-scoped access tokens, an append-only audit chain,
cross-platform local installation with boot auto-start, and a deliberately
pleasant Web UI.

### 1.2 Out of scope (for now)

Multi-tenant hosting, org-wide RBAC, HSM/KMS custody, secret *generation*
services, agent orchestration itself, and cloud-hosted operation of the vault.
Remote exposure beyond the loopback interface is opt-in and gated (§4.4).

### 1.3 Non-negotiables

1. The vault is **sealed at rest**. Plaintext exists only in daemon memory
   while unsealed.
2. **A URL is a reference, not a credential.** Copying a reference URL must
   never be sufficient to read a secret. See [ADR 0002](adr/0002-reference-urls-are-not-credentials.md).
3. Every read, write, seal, unseal, token mint, and revoke is **appended to a
   hash-chained ledger** that cannot be silently rewritten.
4. The repository contains **code and docs only** — never vaults, keys,
   exports, or ledgers.
5. Default bind is `127.0.0.1`. Nothing listens on a routable address without
   an explicit, recorded operator action.

## 2. Why "Chain"

Two chains give the project its name:

- **Custody chain** — human → vault → scoped agent token → single retrieval,
  where each hop is authenticated and narrowed, never widened.
- **Audit chain** — an append-only ledger where record *n* commits to the hash
  of record *n-1*, so tampering with history is detectable. This mirrors the
  receipt discipline used elsewhere in the Bastet family.

## 3. Threat model summary

Full model: [`docs/THREAT_MODEL.md`](THREAT_MODEL.md). The headline risks:

- **Stolen vault file.** Mitigated by envelope encryption with an Argon2id-derived
  key; the file alone is useless.
- **Leaked reference URL.** Mitigated by ADR 0002 — the URL carries no secret and
  no authority.
- **Over-broad agent token.** Mitigated by path/tag-scoped, read-only,
  expiring, revocable tokens with per-token rate limits.
- **Compromised agent process.** Cannot be fully mitigated; contained by
  narrow scopes, short TTLs, retrieval quotas, optional per-read human
  approval, and an audit chain that makes abuse visible after the fact.
- **Prompt-injected agent.** An agent told by a web page to fetch and exfiltrate
  a secret will be *authorized* to fetch whatever its token covers. Therefore
  scope minimization and approval-required items are the primary defense, and
  high-value items (🔥 service accounts, 📜 signing certs) default to
  approval-required.
- **Approval fatigue.** An operator asked to approve too often stops reading the
  prompts, which removes the control while leaving the belief that it exists.
  Addressed by [ADR 0005](adr/0005-approval-and-reminder-model.md): task
  sessions, trust-on-first-use per token × item, tiered defaults, and
  pre-authorization, so that the prompts that remain are worth reading.

## 4. Architecture

### 4.1 Shape

A single Rust binary (`bsc`) that is both CLI and daemon, serving an embedded
React single-page app and a versioned JSON API over loopback HTTP. SQLite in
WAL mode holds encrypted items, metadata, tokens, and the audit chain. This
matches the house stack used by Bastet Workstation (Rust + React + SQLite WAL),
so patterns and review knowledge transfer.

```
Browser (human)  ──TLS/loopback──┐
                                 ├── bsc daemon ── SQLite (WAL)
AI agent (token) ──loopback──────┘        │            ├─ items (ciphertext)
                                          │            ├─ tokens
                                   in-memory DEK cache ├─ audit_chain
                                          │            └─ meta
                                    OS keychain (optional unattended unseal)
```

### 4.2 Cryptography

- **KDF:** Argon2id over the operator passphrase → 32-byte KEK.
  Parameters recorded in the vault header so they can be raised over time.
- **Envelope:** every item version gets a fresh random DEK; the DEK is wrapped
  by the KEK. Rotating the passphrase rewraps DEKs and never re-encrypts item
  bodies.
- **AEAD:** XChaCha20-Poly1305 with a random 24-byte nonce per encryption.
  The item's stable id and version are bound in as associated data, so a
  ciphertext cannot be replayed under a different identity.
- **Metadata:** item *names and paths are encrypted too*; a separate blind
  index over a keyed hash of lowercase name tokens supports search without
  revealing names in the file. Timestamps, sizes, and types stay clear so the
  UI can list a sealed vault's shape without unsealing it.
- **Sealed/unsealed:** the vault boots sealed. Unseal by passphrase in the UI,
  or — when the operator has opted in — unattended at start: from a systemd
  encrypted credential (`--unseal-credential`, servers) or the macOS Keychain
  (`--unseal-keychain`, LaunchAgents). *Implemented 2026-09-04 (M6 step 1);
  Windows DPAPI and Linux Secret Service are not.* Each such unseal is a
  ledger record `unseal_unattended` naming its source; a source that fails
  refuses to start rather than waiting sealed and silent. Auto-reseal on idle
  timeout, on explicit lock, and on suspend where the OS reports it — *not yet
  implemented*.
- **Zeroization:** all key material and plaintext buffers use zeroizing types.

### 4.3 Data model

```
item        id, path (enc), name (enc), type, tags[], env, created, updated,
            expires_at, rotation_period, approval_required, current_version
version     item_id, n, ciphertext, nonce, wrapped_dek, size, created, note
(reference  collapsed in M2: the item id *is* the sref_ value)
token       id, hash, label (enc), scope (enc), created, lifetime, expires_at,
            max_lifetime_until, max_reads, reads_used, rate_limit, created_by,
            revoked_at
session     id, scope (enc), opened, expires_at, closed_at, opened_by
grant       token_id, item_id, approval_id, expires_at
audit       n, prev_hash, hash, ts, actor, action, subject, outcome, meta
approval    id, token_id, item_id, reason, requested_at, expires_at, status,
            decided_at, decided_by, consumed_at, escalation
```

Hierarchy is a path (`prod/aws/billing-account`) plus orthogonal tags, so the
same item can live in one place and still be found many ways.

### 4.4 Access paths

- **Human:** browser on loopback, passphrase-unsealed session cookie,
  short idle timeout, re-auth for reveal/export of approval-required items.
- **Agent (standing token):** `GET /v1/secrets/{sref}` with
  `Authorization: Bearer bsct_…`. The token is minted in the UI, scoped, and
  handed to the agent through its own configuration — not through the URL.
- **Agent (handoff link):** for the copy-paste case the UI can mint a
  **single-use, 60-second, loopback-bound** handoff link. It is a distinct
  code path with its own audit action, and it is off by default.
- **Agent (blocked read):** a read that needs approval, or whose token has
  expired but is still inside its renewal window, returns `202` with an
  `approval_id` and a `Retry-After` rather than a bare denial, so the waiting
  agent has one unambiguous next step. Escalation and auto-deny follow
  [ADR 0005](adr/0005-approval-and-reminder-model.md).
- **Task sessions:** the operator may open a scoped, time-boxed window in which
  in-scope reads are recorded but not interrupted. Windows do not auto-renew.
- **Renewal:** `POST /v1/token/renew` extends an existing token inside its
  renewal window. It never widens scope and never resurrects a token past the
  grace period, so agent configuration never changes.
- **Remote exposure:** opt-in only, requires TLS with a certificate the
  operator supplies, mutual TLS or a network allow-list, and a recorded
  acknowledgement written to the audit chain.
  *Pulled forward on 2026-09-04* for `sec.bastet.tw`: the daemon still binds
  loopback; `bsc serve --public-origin` accepts one external origin, marks the
  cookie `Secure`, throttles logins per forwarded client, and writes
  `exposure_acknowledged`. The operator chose the vault's own authentication
  plus throttling as the first gate, with Cloudflare Access recommended as the
  next step. See [`DEPLOY_REVERSE_PROXY.md`](DEPLOY_REVERSE_PROXY.md).

### 4.5 Local installation

- One artifact per platform, checksummed and (from M6) signed.
- `bsc service install` writes the platform service definition:
  launchd `LaunchAgent` (macOS), a Windows service via SCM with Task Scheduler
  fallback, a systemd **user** unit with `WantedBy=default.target` (Linux).
- `bsc doctor` verifies bind address, file permissions (`0600` vault,
  `0700` directory), service state, keychain availability, and clock sanity.
- Uninstall removes the service and leaves the vault untouched by default.
- Implemented in M4 as launchd LaunchAgent / systemd user unit / Task
  Scheduler logon task, all without elevation; SCM service and installer
  packages are later decisions. Windows note: the logon task runs only when
  the user logs in, like the other two.

### 4.6 Agent interface

The HTTP API is the single source of truth and the single audit entry point.
An MCP server ships inside the same binary (`bsc mcp`) as a thin wrapper over
it and bypasses no check; it is the interface agents should use by default,
because a tool description is a specification aimed at the model, the value
never passes through a shell, and the token never appears in a command the agent
generates. Full reasoning and the tool surface are in
[ADR 0006](adr/0006-mcp-as-the-primary-agent-interface.md).

The agent surface is read-only — `list_secrets`, `get_secret`,
`request_access`, `check_access`, `renew_access`. Writing is something a human
does in the Web UI. A `reason` is mandatory on every path that can release a
value.

Failures return a distinguishable code (`token_expired`, `scope_mismatch`,
`approval_pending`, `approval_timeout`, `approval_denied`, `quota_exhausted`,
`vault_sealed`) together with prose the agent will act on, including an explicit
prohibition against asking a human to paste the secret into a conversation.

## 5. Web UI plan

Detail: [`docs/UX_PLAN.md`](UX_PLAN.md). Principles:

- Emoji-led categories that read at a glance (🔑 ☁️ 🔥 🎫 🖥️ 📜 🗂️), a left
  tree for the path hierarchy, a filter bar for tags/env/expiry.
- Drag-and-drop upload for credential *files* (JSON, PEM, p12) that encrypts
  in place and never writes a plaintext temp file.
- One prominent **📋 Copy reference** button per item, which copies the
  reference URL and shows plainly, in the toast, that the URL alone grants
  nothing.
- Health surfaces: ⏰ expiring soon, 🔄 rotation overdue, 🚨 recent denied
  reads, 🔍 audit trail per item.
- Light and dark, keyboard-first, five-locale ready (zh-Hant default).

## 6. Milestones and gates

| ID | Milestone | Gate |
| --- | --- | --- |
| M0 | Repository and specification baseline | This plan, threat model, ADRs, license, security policy committed and pushed |
| M1 | Crypto core and sealed storage | Argon2id/XChaCha20 envelope, SQLite WAL schema, seal/unseal, zeroization; property tests + known-answer vectors |
| M2 | Daemon API, tokens, audit chain, MCP | Versioned API, scoped tokens, renewal, task sessions, pending-approval protocol, structured agent errors, hash-chain ledger with a verifier, `bsc mcp` server; chain-tamper detection test and an agent-facing error-contract test |
| M3 | Web UI | Upload → encrypt → classify → copy reference, approval inbox, task-session control, ⏰ expiry panel, local OS notifications, per-item audit view; e2e test on all item types |
| M4 | Packaging and auto-start | macOS/Windows/Linux artifacts, `service install`, `doctor`; three-platform CI plus one real-machine reboot survival test per platform |
| M5 | Agent integration | Claude Code / Codex / Agy recipes, CI and script patterns, scope-per-project guidance; a real multi-step agent task completes across a token renewal and an approval |
| M6 | Rotation, delegation, external approval | Rotation workflow, pre-authorization, outbound external approval channel, `use_secret` / `bsc exec` value-free delegation, audit-head anchoring, break-glass export |
| M7 | Hardening and first release | External-review checklist, fuzzing on parsers, signed release, restore-from-backup drill |

No milestone is claimed complete until its gate is met and the evidence is
recorded in this repository and mirrored to BastetMind.

### 6.1 Status

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 | complete, 2026-09-03 | this repository at `2e3197b` and `0f33b25` |
| M1 | complete, 2026-09-03 — 43 tests, three-platform CI run `33761893191` | [`M1_VALIDATION.md`](M1_VALIDATION.md) |
| M2 | complete, 2026-09-03 — 79 tests, three-platform CI run `33766212364` | [`M2_VALIDATION.md`](M2_VALIDATION.md), [`API_CONTRACT.md`](API_CONTRACT.md) |
| M3 | complete, 2026-09-03 — 82 tests, three-platform CI run `33769473982`; e2e gate met by an API-level substitute plus a recorded manual browser pass | [`M3_VALIDATION.md`](M3_VALIDATION.md) |
| M4 | delivered 2026-09-04 — 95 tests, CI run `33777806776` with three release artifacts; LaunchAgent install / kill-restart / uninstall observed on a real Mac; **reboot itself not performed on any platform** | [`M4_VALIDATION.md`](M4_VALIDATION.md) |
| M5 | complete, 2026-09-04 — real Codex CLI and Claude Code runs through `bsc mcp` each crossed a token renewal and a human approval; recipes for Claude Code / Codex / Agy / scripts | [`M5_VALIDATION.md`](M5_VALIDATION.md), [`AGENT_INTEGRATION.md`](AGENT_INTEGRATION.md) |
| M6 | complete, 2026-09-04 — ① unattended unseal, ② `use_secret`, ③ Telegram approval channel, ④ pre-authorization, rotation cadence, passphrase rotation, item deletion, ⑤ audit-head anchoring (`bsc audit --anchor-file`) and break-glass export/import (`bsc export` / `bsc import`) | [`M6_VALIDATION.md`](M6_VALIDATION.md) |
| M7 | not started | — |

## 7. Open questions

Tracked so they are not silently decided by implementation:

1. Should the daemon support **multiple vaults** (per-project separation), or
   one vault with strict path scoping? Leaning multiple, deferred to M2.
2. ~~Backup format.~~ **Resolved 2026-09-04**: `bsc export` writes a `BSCX1`
   bundle — JSON of every item and every version, sealed with Argon2id +
   XChaCha20-Poly1305 under a passphrase that must differ from the vault's,
   header bound as associated data. `bsc import` recreates items as new
   `sref`s in another vault. Tokens, sessions, approvals, grants, and the
   ledger are deliberately not exported. Raw file copy remains a valid
   *backup*; the bundle is for handing secrets across vaults or successors.
3. **TOTP** generation inside the vault: convenient, but it turns the vault
   into a second factor holder alongside the first. Deferred to M6.
4. ~~Whether agent reads should support a use-once wrapper.~~ **Implemented
   2026-09-04 as `use_secret`** (M6 step 2): the daemon proxies one https
   request with the credential injected per a human-set binding (URL patterns,
   header template, methods), behind the same policy as a read plus an SSRF
   guard; the agent never observes the value. `bsc exec` (child-process
   injection) was *not* built — a child process the agent controls can print
   its environment, so it would not deliver the guarantee. Which providers
   support genuinely derived short-lived credentials remains to be surveyed.
5. **BastetAgentOS / Bastet Workstation integration** — BSC as their credential
   provider. Not before M5, and not a design constraint on M1–M4.
6. The default parameters in [ADR 0005](adr/0005-approval-and-reminder-model.md)
   §6 are chosen, not measured. Which of them are actually wrong will only be
   visible after real use; the 5-minute auto-deny and the 30-minute task window
   are the two most likely to need changing.
7. Which external approval channel to bind first. Telegram is the pragmatic
   choice because the operator already runs that infrastructure, but it makes
   an approval control depend on a third-party service being reachable.
8. Whether to add a browser-driven e2e suite (Playwright) for the UI, and if
   so whether to run it on one CI platform only. M3's gate was met by an
   API-level round trip of every type plus a recorded manual pass; that is a
   substitution and should not quietly become the standard.
9. What the daemon should do when the operator is provably away — currently
   every pending request simply auto-denies after five minutes, which may be
   the wrong behavior for a long unattended batch.

## 8. Synchronization duty

Project documents and history are mirrored to the BastetMind Obsidian wiki and
to AgentMemoryOS at the end of any session that changes scope, architecture,
decisions, deployment state, or verification results. See [`AGENTS.md`](../AGENTS.md).

> **2026-09-04:** first tagged build `v0.1.0` (M0–M6) published as a draft GitHub Release with SHA256SUMS and provenance attestations; production runs `0.1.0+f23d51a`. Signed binaries, dependency refresh and the hardening pass remain M7.
