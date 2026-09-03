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

### Status

- No implementation yet. M0 (repository and specification baseline) is the
  active milestone; M1 onwards has not started.
