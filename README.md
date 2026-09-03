# Bastet Secret Chain 🔐⛓️

**📖 Manuals:** [繁體中文](docs/manual/zh-Hant/guide.md) · [简体中文](docs/manual/zh-Hans/guide.md) · [English](docs/manual/en/guide.md) · [日本語](docs/manual/ja/guide.md) · [한국어](docs/manual/ko/guide.md) — [all manuals](docs/manual/)

A local-first, self-hosted vault for sensitive credentials — built so that **AI
agents can fetch exactly the secret they need, at the moment they need it,
without the secret ever living in a URL, a prompt, or a shell history.**

Humans put credentials in through a Web UI. Agents take them out through an
authenticated reference. Every retrieval is appended to a tamper-evident chain.

> **Status: 0.1.0, the first tagged build.** M0–M6 are complete: crypto core,
> daemon API, agent tokens, hash-chained ledger, MCP server, Web UI, packaging
> and auto-start, real-agent integration, and the M6 set — unattended unseal,
> use-without-seeing, an outbound approval channel, passphrase rotation,
> pre-authorization, ledger anchoring and break-glass export. 127 passing
> tests on three platforms. One deployment is running behind nginx with the
> approval channel verified end to end against the real Telegram Bot API.
> Not yet done: signed binaries, an external review, the hardening pass (M7).
> Evidence and gaps: [`docs/M6_VALIDATION.md`](docs/M6_VALIDATION.md).

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
4. The agent fetches through the MCP server, and the read is written into the
   audit chain — after human approval if the item calls for it.

Agents should reach the vault through the built-in **MCP server** (`bsc mcp`)
rather than raw HTTP: a tool description is a specification the model actually
reads, the value never passes through a shell, and the token never appears in a
command the agent generates. The HTTP API remains the sole source of truth and
audit entry point for CI, scripts, and non-MCP consumers —
[ADR 0006](docs/adr/0006-mcp-as-the-primary-agent-interface.md).

For an item that only ever goes to one service, the agent need not see it at
all: bind the item to a URL pattern and a header, and `use_secret` has the
daemon make the call with the credential injected.

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
- **Hash-chained audit ledger** for every read, mint, and revoke, with daily
  anchors kept outside the vault — [ADR 0004](docs/adr/0004-hash-chained-audit-ledger.md)
- **Approval without fatigue**: task sessions, trust-on-first-use per
  token × item, pre-authorization, tiered defaults, and an escalating reminder
  ladder that ends in a definite auto-deny — [ADR 0005](docs/adr/0005-approval-and-reminder-model.md)
- **Loopback by default.** Remote exposure is opt-in, gated, and recorded.
  External approval channels are outbound-only and never carry secrets.
- **Cross-platform local install** with `bsc service install` for launchd,
  Windows Task Scheduler, and systemd user units; a system unit, unattended
  unseal and an anchor timer for servers.

## Documentation

**Manuals** — installation, daily use, and agent integration, in five
languages: [`docs/manual/`](docs/manual/).

**Design and reference** — English, and normative:

| Document | Purpose |
| --- | --- |
| [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) | **Single authority** for scope, architecture, milestones, gates |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, adversaries, trust boundaries, residual risks |
| [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) | HTTP API and MCP tool contract, error codes, `do_not` text |
| [`docs/UX_PLAN.md`](docs/UX_PLAN.md) | Web UI information architecture and interactions |
| [`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md) | Per-client MCP configuration and what to tell the agent |
| [`docs/DEPLOY_REVERSE_PROXY.md`](docs/DEPLOY_REVERSE_PROXY.md) | Running behind nginx / Cloudflare with `--public-origin`; what it does and does not protect |
| [`docs/M1_VALIDATION.md`](docs/M1_VALIDATION.md) … [`M6`](docs/M6_VALIDATION.md) | Per-milestone test evidence and what is explicitly **not** done |
| [`docs/adr/`](docs/adr) | Architecture decision records 0001–0006 |
| [`CHANGELOG.md`](CHANGELOG.md) | History of changes |

## Installing

```sh
sh scripts/install.sh v0.1.0            # macOS, Linux
.\scripts\install.ps1 -Version v0.1.0   # Windows
```

Both verify the archive against the `SHA256SUMS` published with the release.
Read them before running them; they are not meant to be piped from the network
into a shell. Release binaries are **not signed with a project key yet** —
scheduled for M7 — so also verify the build provenance:

```sh
gh attestation verify bsc-0.1.0-<target>.tar.gz --repo yamantaka520/Bastet-Secret-Chain
```

From source, at any commit:

```sh
npm --prefix ui ci && npm --prefix ui run build
cargo install --path crates/bsc --locked
```

The full procedure, including servers, is in the
[installation manual](docs/manual/en/install.md).

## Running it

```sh
bsc init                      # creates ~/.bsc/vault.bsc, prompts for a passphrase
bsc service install           # start now and at every login (launchd / systemd --user / Task Scheduler)
bsc doctor                    # ✅/⚠️/❌ checklist: permissions, ledger, daemon, UI, auto-start, clock
bsc serve                     # or run it in the foreground instead of installing the service
bsc audit --anchor-file ~/anchors/bsc.jsonl   # verify the ledger offline and anchor it
bsc export --out backup.bscx  # break-glass export under a separate passphrase
```

`bsc service install --dry-run` prints the definition and the commands without
touching anything. `bsc --version` reports the build (`0.1.0+f23d51a`) so you
can tell which binary a machine is running.

Open `http://127.0.0.1:8787/`, unseal, and work in the UI. The same things are
reachable over the human API:

```sh
curl -c jar -H 'X-BSC-Client: cli' -H 'Content-Type: application/json' \
  -d '{"passphrase":"…"}' http://127.0.0.1:8787/v1/vault/unseal
curl -b jar -H 'X-BSC-Client: cli' -H 'Content-Type: application/json' \
  -d '{"path":"prod/gcp","name":"firebase-admin","type":"service_account","value":"…"}' \
  http://127.0.0.1:8787/v1/items
curl -b jar -H 'X-BSC-Client: cli' -H 'Content-Type: application/json' \
  -d '{"label":"deploy-bot","scope":{"paths":["prod"]},"lifetime":86400}' \
  http://127.0.0.1:8787/v1/tokens        # the bsct_ value appears once, here
```

Give an agent the MCP server, not the token in a prompt:

```json
{ "mcpServers": { "bsc": { "command": "bsc", "args": ["mcp"],
  "env": { "BSC_TOKEN": "bsct_…" } } } }
```

## Building

```sh
npm --prefix ui ci && npm --prefix ui run build   # the UI, embedded on the next cargo build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p bsc-crypto --example gen_vectors     # regenerates the KAT lines
```

## Project policies

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Apache-2.0 license](LICENSE) · [Notices](NOTICE)

This repository holds **source and documentation only**. Vault files, keys,
exports, tokens, and audit ledgers must never be committed.
