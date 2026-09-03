# Contributing

## Before you start

[`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) is the single authority for scope,
architecture, milestones, and gates. If a change disagrees with it, change the
plan first, in the same pull request, with the reasoning recorded.

Decisions that shape the system go in [`docs/adr/`](docs/adr) as a new numbered
record. Superseding an existing ADR is done explicitly — mark the old one
`Superseded by ADR NNNN` rather than editing its decision away.

## Security review gate

Every pull request must be able to answer these, from
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §5:

- Does it put secret material in a URL, log line, error message, process
  argument, or crash report?
- Does it bypass the audit chain? No code path may return a secret without
  appending a record first.
- Does it widen a default — access, exposure, or lifetime?
- Is new key material zeroized, and are new parsers fuzzed?

## Rules that do not bend

1. No real credentials anywhere in the repository, including tests and issues.
2. No plaintext secret written to disk, ever — not to temp files, not to caches.
3. No new listener on a routable address without the gating described in the
   master plan.
4. Cryptographic primitives come from established audited crates. Do not
   hand-roll them.

## Web UI

`ui/` is a Vite + React + TypeScript app with no UI library. `npm --prefix ui
run typecheck` and `npm --prefix ui run build` must pass; the daemon embeds
`ui/dist` on the next `cargo build`. Strings live in `ui/src/i18n.ts` in both
locales — no hard-coded text in components. Nothing sensitive goes in
`localStorage`; only theme and locale do.

## Commits

Present-tense subject lines describing the change, with the reasoning in the
body when it is not obvious. Update [`CHANGELOG.md`](CHANGELOG.md) under
`Unreleased` in the same commit as the change it describes.
