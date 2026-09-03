# Bastet Secret Chain — Master Plan

**Status:** accepted baseline, 2026-09-03. No implementation yet.
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
  or from the OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service)
  when the operator has opted into unattended start. Auto-reseal on idle
  timeout, on explicit lock, and on suspend where the OS reports it.
- **Zeroization:** all key material and plaintext buffers use zeroizing types.

### 4.3 Data model

```
item        id, path (enc), name (enc), type, tags[], env, created, updated,
            expires_at, rotation_period, approval_required, current_version
version     item_id, n, ciphertext, nonce, wrapped_dek, size, created, note
reference   item_id, stable public ref id  ("sref_…"), created, revoked_at
token       id, label, scope_paths[], scope_tags[], read_only, expires_at,
            max_reads, reads_used, rate_limit, created_by, revoked_at
audit       n, prev_hash, hash, ts, actor, action, subject, outcome, meta
approval    item_id, token_id, requested_at, decided_at, decision, decided_by
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
- **Remote exposure:** opt-in only, requires TLS with a certificate the
  operator supplies, mutual TLS or a network allow-list, and a recorded
  acknowledgement written to the audit chain.

### 4.5 Local installation

- One artifact per platform, checksummed and (from M6) signed.
- `bsc service install` writes the platform service definition:
  launchd `LaunchAgent` (macOS), a Windows service via SCM with Task Scheduler
  fallback, a systemd **user** unit with `WantedBy=default.target` (Linux).
- `bsc doctor` verifies bind address, file permissions (`0600` vault,
  `0700` directory), service state, keychain availability, and clock sanity.
- Uninstall removes the service and leaves the vault untouched by default.

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
| M2 | Daemon API, tokens, audit chain | Versioned API, scoped tokens, hash-chain ledger with a verifier; chain-tamper detection test |
| M3 | Web UI | Upload → encrypt → classify → copy reference, per-item audit view; e2e test on all item types |
| M4 | Packaging and auto-start | macOS/Windows/Linux artifacts, `service install`, `doctor`; three-platform CI plus one real-machine reboot survival test per platform |
| M5 | Agent integration | Documented fetch patterns, MCP server, env-injection helper, Claude Code / Codex / Agy recipes |
| M6 | Rotation, expiry, approvals | Expiry alerts, rotation workflow, approval-required reads, break-glass export |
| M7 | Hardening and first release | External-review checklist, fuzzing on parsers, signed release, restore-from-backup drill |

No milestone is claimed complete until its gate is met and the evidence is
recorded in this repository and mirrored to BastetMind.

## 7. Open questions

Tracked so they are not silently decided by implementation:

1. Should the daemon support **multiple vaults** (per-project separation), or
   one vault with strict path scoping? Leaning multiple, deferred to M2.
2. **Backup format** — encrypted export that a future version can still read,
   versus raw file copy. Needs a decision before M4 packaging.
3. **TOTP** generation inside the vault: convenient, but it turns the vault
   into a second factor holder alongside the first. Deferred to M6.
4. Whether agent reads should support a **use-once wrapper** (agent receives a
   short-lived derived credential rather than the stored one) for providers
   that support it. Would materially reduce blast radius; deferred to M6.
5. **BastetAgentOS / Bastet Workstation integration** — BSC as their credential
   provider. Not before M5, and not a design constraint on M1–M4.

## 8. Synchronization duty

Project documents and history are mirrored to the BastetMind Obsidian wiki and
to AgentMemoryOS at the end of any session that changes scope, architecture,
decisions, deployment state, or verification results. See [`AGENTS.md`](../AGENTS.md).
