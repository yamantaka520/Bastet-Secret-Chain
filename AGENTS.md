# Working rules for this repository

## Authority

[`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) is the single authority for scope,
architecture, milestones, and gates. Read it, and the most recent entries in
[`CHANGELOG.md`](CHANGELOG.md), before proposing or making a change.

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
