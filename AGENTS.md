# Working rules for this repository

## Authority

[`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) is the single authority for scope,
architecture, milestones, and gates. Read it, and the most recent entries in
[`CHANGELOG.md`](CHANGELOG.md), before proposing or making a change.

## What never goes in this repository

This repository is public, and a credential vault's repository is a map of
where credentials live. Two categories are banned outright, and CI fails on
both:

1. **Credential material** — vault files, exports, tokens, keys, passphrases,
   anchor files.
2. **Deployment specifics of any particular installation** — real hostnames,
   internal or public IP addresses, host names, OS and package versions,
   tunnel or account identifiers, SSH accounts, host key fingerprints, chat
   ids, allow-listed source addresses, or the statement that some port is
   open somewhere.

Documentation describes **how to run this software**, with `example.com` and
placeholders. Where one copy of it happens to run, and how that host is
reached, belongs in the operator's own notes. This rule exists because it was
broken once, on 2026-09-04, when the reverse-proxy document accumulated a
live deployment's address, hostnames, SSH allow-list and host key
fingerprints; see the commit that removed them.

Work that is infrastructure rather than product — publishing SSH through a
tunnel, wiring a firewall — does not get documented here at all, however
useful it was on the day.

## Synchronization duty

Project documents and history are mirrored outside this repository. At the end
of any session that changes scope, architecture, decisions, deployment state,
verification results, or known gaps, all of the following must be updated:

1. **This repository** — the affected document, an ADR if a decision was made,
   and `CHANGELOG.md`.
2. **BastetMind** (Obsidian wiki at `~/Documents/BastetMind/BastetMind`) —
   a source page under `10-原始資料/` when there is a new verifiable snapshot,
   the topic page `20-知識庫/主題/Bastet Secret Chain.md`, `index.md`, and the
   append-only `log.md`. Follow that vault's `AGENTS.md`.
3. **AgentMemoryOS** — durable facts and decisions worth recalling in a later
   session.

Record progress, decisions, verification results, known gaps, and document
conflicts. Do not record one-off operational trivia, anything the repository
already states, or any secret.

## Never

- Commit vault files, key material, exported secrets, service-account JSON,
  OAuth secrets, SSH keys, certificates, tokens, or audit ledgers.
- Write a real credential into a document, a test fixture, BastetMind, or
  persistent memory.
- Claim a milestone complete before its gate in the master plan is met and the
  evidence is recorded.
