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

- **M2 — `bsc-store` access layer**: tokens stored as a SHA-256 hash with
  encrypted label and scope; renewal inside the final quarter of life plus a
  five-minute grace, capped at a maximum lifetime, never widening scope; read
  quotas; task sessions with an eight-hour cap and no renewal; approvals with
  deduplicated pending requests, decisions, timeouts, and an escalation
  ladder recorded step by step; trust-on-first-use grants capped at token
  expiry; `local_approval_only`; an injectable clock; `verify_passphrase`.
- **M2 — `bsc-daemon`**: `/v1` agent surface (`GET /secrets`,
  `GET /secrets/{sref}[/versions/{n}]`, `POST /access-requests`,
  `GET /access-requests/{apr}`, `POST /token/renew`, `GET /token`) and human
  surface (vault, items, versions, reveal, tokens, sessions, approvals, audit,
  handoff stub); `202 approval_pending` with `Retry-After` and `Location`;
  the full error contract with `next_action` and `do_not`; cookie +
  `X-BSC-Client` + `Origin` same-origin discipline; per-token rate limiting;
  approval ticker with a `Notifier` seam; loopback-only `serve`.
- **M2 — `bsc-mcp`**: JSON-RPC 2.0 stdio server with exactly five read-only
  tools, safety text in descriptions and `instructions`, reason sent in a
  header, results identical to the HTTP body, `isError` false for `202`.
- **M2 — `bsc`**: `init`, `serve`, `mcp`, `audit`.
- `docs/M2_VALIDATION.md`; `docs/API_CONTRACT.md` revised to what was built
  (renewable expiry is `401`, reveal is `POST`, sessions cover local-only
  items, item id is the sref, human codes and same-origin added).

- **M3 — `ui/`**: the operator's single-page app (Vite 7, React 19,
  TypeScript, no UI library) — login/unseal, overview tiles, secrets with a
  path tree and type/env/text filters, item drawer with detail, versions, and
  per-item audit, new-item modal with an emoji type grid and file drop,
  tokens with a shown-once mint sheet and MCP config snippet, approval inbox
  with verbatim reason, countdown, and `a`/`d` keys, task-session control in
  the header, expiry panel, audit-chain browser; zh-Hant and English; light
  and dark; browser notifications opt-in.
- **M3 — daemon**: serves the embedded UI from `/` with CSP and hardening
  headers, `build.rs` placeholder when the UI is not built,
  `GET /v1/audit?subject=`, `OsNotifier` (osascript / notify-send /
  PowerShell) as the default for `bsc serve`, `bsc init --passphrase-stdin`.
- `docs/M3_VALIDATION.md`, including the recorded manual browser pass and
  the stated e2e substitution.

- **M4 — `bsc service install|uninstall|status`**: launchd LaunchAgent,
  systemd user unit, or Task Scheduler logon task, user-level and unelevated,
  with `--dry-run`; definitions are unit-tested for every platform.
- **M4 — `bsc doctor`**: ✅/⚠️/❌ checklist over file permissions, header,
  audit chain, writability, loopback, daemon, UI, auto-start, notifications,
  clock; non-zero exit only on ❌.
- **M4 — CI**: release artifacts for Linux/macOS/Windows with the UI embedded,
  `.sha256`, unpacked-archive smoke test, uploaded on every push; `plutil
  -lint` and `systemd-analyze verify` on generated definitions; dormant
  tag-triggered `release.yml` with `SHA256SUMS`, provenance attestations, and
  a draft GitHub Release; `scripts/install.sh` and `install.ps1` with checksum
  verification.
- `docs/M4_VALIDATION.md`, which states that the reboot survival test was not
  performed on any platform.

- **Reverse-proxy exposure (pulled forward from M6/M7)**: `bsc serve
  --public-origin <scheme://host>` accepts that Origin on the human surface,
  marks the session cookie `Secure` on https, keys the new login throttle
  (5 failed attempts per client per 10 minutes) on the first `X-Forwarded-For`
  hop, records `exposure_acknowledged` at start, and shows the origin in
  `/v1/vault/status`; `bsc service install --public-origin` bakes it into the
  definition. Without the flag `X-Forwarded-For` is ignored and the throttle is
  one local bucket. `deploy/` holds the nginx site, proxy snippet, and a
  hardened system unit; `docs/DEPLOY_REVERSE_PROXY.md` explains the trade-offs.
- **Fixed:** the `bsc` binary had no TLS backend (`reqwest` without rustls),
  so `bsc mcp` and `bsc doctor` could not reach an https daemon; `doctor`
  failed every non-loopback URL instead of consulting the daemon's declared
  `public_origin`. Both found on the first remote check of a deployment.
- `sec.bastet.tw` is live behind nginx and Cloudflare (system unit, user
  `bsc`, sealed until unsealed in the UI); `ssh.bastet.tw` routes through the
  existing tunnel with Access allowing three addresses — denied and allowed
  paths both observed.
- `deploy/cloudflare-ssh-tunnel.sh`: idempotently publishes a host's sshd on
  an existing remotely-managed Cloudflare Tunnel (ingress + proxied CNAME +
  Access app with a Bypass-by-IP policy), token read from a file, never
  printed.

- **M5 — agent integration**: `docs/AGENT_INTEGRATION.md` (Claude Code,
  Codex, Agy/Gemini, scripts and CI, scope-per-project, troubleshooting,
  anti-patterns), `scripts/m5-gate.sh`, and a recorded real-agent run in
  which Codex CLI, through `bsc mcp`, met an expired token, renewed it, hit
  `approval_pending`, waited in `check_access` while a human approved, and
  answered with only the requested field.

### Status

- M5 gate met on 2026-09-04 with Codex CLI and then Claude Code; Agy and
  Grok documented but not run end to end.
- M4 delivered on 2026-09-04: 95 passing tests and three release artifacts on
  CI run `33777806776`; the LaunchAgent was installed, hard-killed, watched
  restart, and removed on a real Mac; the reboot itself was not performed on
  any platform. No tag, no release.
- M3 gate met on 2026-09-03: 82 passing tests locally and on Ubuntu, macOS,
  and Windows with the UI built and embedded (CI run `33769473982`). M4
  (packaging and auto-start) not started. No release.
- M2 gate met on 2026-09-03: 79 passing tests locally and on Ubuntu, macOS,
  and Windows (CI run `33766212364`). M3 (Web UI) not started. No release.
- M1 gate met on 2026-09-03: 43 passing tests locally and on Ubuntu, macOS,
  and Windows (CI run `33761893191`). M2 has a contract but no code. No
  release.
