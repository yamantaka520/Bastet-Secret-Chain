# Threat Model

**Status:** baseline, 2026-09-03. Revisit at every milestone gate.
Scope: the Bastet Secret Chain vault, daemon, Web UI, and agent retrieval path.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Stored secret material | Direct access to cloud accounts, production data, money |
| Master passphrase / KEK | Unlocks everything |
| Agent tokens | Scoped but real authority, often held by automated processes |
| Audit chain | The only record of what was taken and by whom |
| Item metadata | Names and paths leak infrastructure shape even without values |

## 2. Trust boundaries

1. **Disk ↔ daemon.** Everything on disk is untrusted ciphertext. A stolen
   vault file must be useless without the passphrase.
2. **Daemon ↔ browser.** Loopback only by default. The browser holds a session,
   never the KEK.
3. **Daemon ↔ agent.** The agent is *semi-trusted*: authenticated, scoped, and
   assumed to be potentially manipulated by its own inputs.
4. **Host OS.** Trusted. An attacker with root or with the operator's live
   session is out of scope for cryptographic defense; audit is the residual
   control.

## 3. Adversaries and mitigations

### A1 — Attacker with the vault file (backup, stolen laptop disk, synced folder)

Envelope encryption; Argon2id with parameters chosen against GPU attack and
recorded in the header so they can be raised. Item names and paths are also
encrypted. **Residual:** timestamps, item counts, sizes, and types are visible,
which leaks activity patterns. Accepted for UI usability while sealed.

### A2 — Attacker who obtains a copied reference URL

The reference URL identifies an item and grants nothing. Retrieval requires a
bearer token presented in a header. See [ADR 0002](adr/0002-reference-urls-are-not-credentials.md).
This is the single most important decision in the project, because URLs end up
in shell history, process arguments, proxy and server logs, browser history,
chat transcripts, and agent context windows — all places a secret must not be.

**Residual:** the optional handoff link *does* carry a single-use token in the
URL. It is off by default, expires in 60 seconds, is bound to loopback, is
invalidated on first use, and writes its own audit action.

### A3 — Attacker who obtains an agent token

Tokens are read-only, scoped to path prefixes and tags, expiring, rate-limited,
optionally read-capped, and revocable from the UI in one click. Every use is
recorded with the token id. **Residual:** anything inside the token's scope is
lost until revocation. Mitigation is operational: mint the narrowest token that
does the job, prefer per-task tokens, and review the audit chain.

### A4 — Prompt-injected or misbehaving agent

An agent instructed by hostile content to fetch and exfiltrate secrets will be
*authorized* for whatever its token covers, so cryptography cannot help.
Controls: minimal scope, short TTL, read quotas, and **approval-required
items** — high-value classes (🔥 service accounts, ☁️ cloud root keys,
📜 signing certificates) default to requiring an explicit human approval in the
UI before each release, with the requesting token and reason shown.

### A4b — Approval fatigue

An operator prompted on every read learns to approve reflexively. The control
then exists in the code and not in reality, which is worse than no control,
because scopes and lifetimes get set as if a human were checking. Mitigated
structurally rather than by exhortation: task sessions, trust-on-first-use per
token × item inside a window, tiering so only high-value classes prompt by
default, and pre-authorization for known work — all in
[ADR 0005](adr/0005-approval-and-reminder-model.md). **Residual:** a task
session is a real widening of authority for its duration; it is scoped,
time-boxed, non-renewing, and fully recorded, and it is the first thing to
review after an incident.

### A4c — Abuse of the notification and approval channel

An external approval channel is a new path into a security decision. Controls:
the daemon connects **outbound only**, so no inbound port is opened; the
message carries the item label, requesting token label, and stated reason but
**never secret material and never a link that alone releases one**; approval is
bound to a chat identity registered once from the local UI; and items may be
flagged local-approval-only, so the external channel can notify but not
approve. **Residual:** the approval control now depends on a third-party
service being reachable, and a compromised messaging account can approve
anything not flagged local-only.

### A5 — Local process snooping the daemon

Loopback binding does not authenticate the peer. Controls: tokens required on
every call, vault file `0600` and directory `0700`, no secrets in process
arguments or environment by default, and on Unix an optional peer-credential
check for the local socket path. **Residual:** any local process that can read
the operator's browser session or a token file inherits that authority.

### A6 — Tampering with history

Each audit record commits to the hash of its predecessor; `bsc audit verify`
recomputes the chain. Deleting or editing a record breaks the chain and is
detectable. **Residual:** truncation of the tail is detectable only if the head
hash is anchored elsewhere — periodic anchoring (printed, or written to a
separate append-only store) is deferred to M6.

### A7 — Network exposure mistakes

Default bind is `127.0.0.1`. Binding to a routable address requires an explicit
flag, a supplied TLS certificate, mutual TLS or a network allow-list, and writes
an acknowledgement record into the audit chain. `bsc doctor` reports a loud
warning whenever the daemon is reachable off-host.

### A8 — Supply chain

Dependencies pinned with lockfiles; release artifacts checksummed and, from M6,
signed. Cryptographic primitives come from established audited crates rather
than hand-rolled code.

## 4. Explicitly out of scope

Defense against a compromised host OS, malicious kernel or hypervisor, hardware
key extraction, and coercion of the operator. Multi-tenant isolation is out of
scope because the vault is single-operator by design.

## 5. Review checklist for each milestone gate

- Does any new surface put secret material in a URL, log line, error message,
  process argument, or crash report?
- Does any new code path bypass the audit chain?
- Does any new default widen access, exposure, or lifetime?
- Are new key materials zeroized, and are new parsers fuzzed?
- Does it increase how often the operator is prompted? If so, it must argue
  against ADR 0005, because prompt frequency is a security parameter.
- Can a value be released without a `reason` recorded?
- Does any error path answer with an undifferentiated failure that an agent
  would resolve by improvising?
