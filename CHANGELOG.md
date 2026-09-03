# Changelog

All notable changes to Bastet Secret Chain are recorded here.
This project follows [Semantic Versioning](https://semver.org/) once a first
release exists. Until then every change lands under `Unreleased`.

## [Unreleased]

### Added

- Repository baseline: Apache-2.0 license, notices, security policy,
  contribution guide, hardened `.gitignore` for a secret-handling repository.
- `docs/MASTER_PLAN.md` as the single authority for scope, architecture,
  milestones, and gates.
- `docs/THREAT_MODEL.md` recording assets, adversaries, trust boundaries, and
  the explicit decision that a copied URL is a reference, never a credential.
- `docs/UX_PLAN.md` describing the Web UI information architecture, emoji
  category system, and copy-to-reference interaction.
- Architecture decision records `0001`–`0004`.
- `AGENTS.md` recording the BastetMind and AgentMemoryOS synchronization duty.

- Architecture decision records `0005` (approval and reminder model) and `0006`
  (MCP as the primary agent interface, HTTP API as the sole source of truth).
- Approval model: task sessions, trust-on-first-use per token × item, tiered
  approval defaults, pre-authorization, a 0 s / 20 s / 60 s escalation ladder,
  and a definite auto-deny so a waiting agent is never stranded.
- Agent interface: read-only MCP tool surface with a mandatory `reason`,
  token renewal that never widens scope, and distinguishable error codes
  carrying instructions the model will act on — including an explicit
  prohibition against asking a human to paste a secret into a conversation.
- Threat model entries `A4b` (approval fatigue) and `A4c` (abuse of the
  notification and approval channel), plus three new review-gate questions.

### Changed

- The MCP server moved from M5 to the end of M2; building the primary agent
  interface late would let the HTTP API's shape drift.
- M3 now includes the approval inbox, task-session control, expiry panel, and
  local notifications. M6 is now rotation, delegation, and external approval.
- Master plan open question 4 (use-once wrappers) resolved in direction as
  `use_secret` / `bsc exec` value-free delegation, scheduled for M6. Four new
  open questions recorded, including that ADR 0005's default parameters are
  chosen rather than measured.

- **M1 — `bsc-crypto`**: Argon2id KDF with stored parameters and an enforced
  minimum, XChaCha20-Poly1305 envelope encryption with per-version data keys
  and identity-binding associated data, direct field encryption for names,
  paths, and tags, HKDF-derived blind index, zeroizing key types, opaque
  decryption failure. 19 property tests and 4 known-answer vectors.
- **M1 — `bsc-store`**: SQLite WAL vault with `0600` permissions, sealed/
  unsealed lifecycle with a header verifier, items and append-only versions,
  exact-token search over the blind index, and a SHA-256 hash-chained audit
  ledger whose `secret_read` record is written before decryption. Sealed
  reads and rejected passphrases are recorded as `denied`. 20 tests including
  tamper detection and a documented tail-truncation residual.
- `docs/API_CONTRACT.md`: v1 HTTP API and MCP tool surface, identifier and
  token formats, the `202 approval_pending` flow, renewal and task-session
  semantics, and the full error table with `next_action` / `do_not` text.
- `docs/M1_VALIDATION.md`: evidence and an explicit not-done list.
- GitHub Actions CI: fmt, clippy `-D warnings`, tests on Ubuntu/macOS/Windows,
  KAT regeneration check, and a credential-pattern scan of the tree.

### Status

- M1 delivered locally on 2026-09-03 with 43 passing tests; three-platform CI
  evidence pending first run. M2 has a contract but no code. No release.
