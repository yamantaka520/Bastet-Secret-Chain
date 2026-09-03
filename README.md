# Bastet Secret Chain 🔐⛓️

A local-first, self-hosted vault for sensitive credentials — built so that **AI
agents can fetch exactly the secret they need, at the moment they need it,
without the secret ever living in a URL, a prompt, or a shell history.**

Humans put credentials in through a Web UI. Agents take them out through an
authenticated reference. Every retrieval is appended to a tamper-evident chain.

> **Status: M0 — repository and specification baseline.**
> This repository currently contains the accepted plan, threat model, and
> architecture decisions. There is no implementation yet.

## What it stores

🔐 logins · 🔑 API keys · ☁️ AWS/GCP/Azure keys · 🔥 Google & Firebase service
account JSON · 🎫 OAuth client secrets and refresh tokens · 🖥️ SSH keys ·
📜 TLS and signing certificates · 🗂️ any other credential file

Organized by a path hierarchy plus orthogonal tags, with versioning, rotation
history, and expiry tracking.

## How agents use it

1. Store a credential in the Web UI. It is encrypted before it touches disk.
2. Press **📋 Copy reference** to get a stable URL such as
   `http://127.0.0.1:8787/v1/secrets/sref_7Qn4…`
3. Mint a **scoped, expiring, revocable token** for the agent.
4. The agent fetches with `Authorization: Bearer bsct_…`, and the read is
   written into the audit chain.

**The reference URL alone grants nothing.** That is deliberate and it is the
project's defining constraint — see
[ADR 0002](docs/adr/0002-reference-urls-are-not-credentials.md). URLs end up in
shell history, process lists, proxy logs, and agent transcripts; secrets must
not follow them there.

## Design in brief

- **One Rust binary** (`bsc`) that is CLI, daemon, and web server, with the
  React UI embedded and SQLite (WAL) as the store — [ADR 0001](docs/adr/0001-single-rust-binary-with-embedded-web-ui.md)
- **Envelope encryption**: Argon2id → KEK, per-version data keys,
  XChaCha20-Poly1305, encrypted item names with a blind search index —
  [ADR 0003](docs/adr/0003-envelope-encryption-with-argon2id-and-xchacha20.md)
- **Hash-chained audit ledger** for every read, mint, and revoke —
  [ADR 0004](docs/adr/0004-hash-chained-audit-ledger.md)
- **Loopback by default.** Remote exposure is opt-in, gated, and recorded.
- **Cross-platform local install** with `bsc service install` for launchd,
  Windows services, and systemd user units.

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) | **Single authority** for scope, architecture, milestones, gates |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, adversaries, trust boundaries, residual risks |
| [`docs/UX_PLAN.md`](docs/UX_PLAN.md) | Web UI information architecture and interactions |
| [`docs/adr/`](docs/adr) | Architecture decision records |
| [`CHANGELOG.md`](CHANGELOG.md) | History of changes |

## Roadmap

M0 baseline → M1 crypto core → M2 daemon API, tokens, audit chain → M3 Web UI →
M4 packaging and auto-start → M5 agent integration → M6 rotation, expiry,
approvals → M7 hardening and first release. Gates are defined in the master
plan; nothing is claimed done until its gate is met.

## Project policies

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Apache-2.0 license](LICENSE) · [Notices](NOTICE)

This repository holds **source and documentation only**. Vault files, keys,
exports, and audit ledgers must never be committed.
