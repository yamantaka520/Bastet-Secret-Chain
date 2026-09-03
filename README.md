# Bastet Secret Chain 🔐⛓️

A local-first, self-hosted vault for sensitive credentials — built so that **AI
agents can fetch exactly the secret they need, at the moment they need it,
without the secret ever living in a URL, a prompt, or a shell history.**

Humans put credentials in through a Web UI. Agents take them out through an
authenticated reference. Every retrieval is appended to a tamper-evident chain.

> **Status: M1 delivered locally; M2 contract drafted.**
> `bsc-crypto` and `bsc-store` implement the envelope encryption, sealed
> SQLite vault, blind index, and hash-chained ledger with 43 passing tests.
> There is no daemon, API, MCP server, or UI yet — their shape is fixed in
> [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md). Evidence and explicit gaps:
> [`docs/M1_VALIDATION.md`](docs/M1_VALIDATION.md).

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

Agents should reach the vault through the built-in **MCP server** (`bsc mcp`)
rather than raw HTTP: a tool description is a specification the model actually
reads, the value never passes through a shell, and the token never appears in a
command the agent generates. The HTTP API remains the sole source of truth and
audit entry point for CI, scripts, and non-MCP consumers —
[ADR 0006](docs/adr/0006-mcp-as-the-primary-agent-interface.md).

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
- **Approval without fatigue**: task sessions, trust-on-first-use per
  token × item, tiered defaults, and an escalating reminder ladder that ends in
  a definite auto-deny — [ADR 0005](docs/adr/0005-approval-and-reminder-model.md)
- **Loopback by default.** Remote exposure is opt-in, gated, and recorded.
  External approval channels are outbound-only and never carry secrets.
- **Cross-platform local install** with `bsc service install` for launchd,
  Windows services, and systemd user units.

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) | **Single authority** for scope, architecture, milestones, gates |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, adversaries, trust boundaries, residual risks |
| [`docs/UX_PLAN.md`](docs/UX_PLAN.md) | Web UI information architecture and interactions |
| [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) | HTTP API and MCP tool contract, error codes, `do_not` text |
| [`docs/M1_VALIDATION.md`](docs/M1_VALIDATION.md) | M1 test evidence and what is explicitly not done |
| [`docs/adr/`](docs/adr) | Architecture decision records 0001–0006 |
| [`CHANGELOG.md`](CHANGELOG.md) | History of changes |

## Roadmap

M0 baseline → M1 crypto core → M2 daemon API, tokens, audit chain, MCP server →
M3 Web UI →
M4 packaging and auto-start → M5 agent integration → M6 rotation, delegation,
external approval → M7 hardening and first release. Gates are defined in the master
plan; nothing is claimed done until its gate is met.

## Building

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p bsc-crypto --example gen_vectors   # regenerates the KAT lines
```

## Project policies

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Apache-2.0 license](LICENSE) · [Notices](NOTICE)

This repository holds **source and documentation only**. Vault files, keys,
exports, and audit ledgers must never be committed.
