# ADR 0005 — Approval and reminder model

- **Status:** accepted, 2026-09-03
- **Deciders:** project owner
- **Related:** [ADR 0002](0002-reference-urls-are-not-credentials.md), [ADR 0004](0004-hash-chained-audit-ledger.md), [ADR 0006](0006-mcp-as-the-primary-agent-interface.md)

## Context

Short-lived, approval-required reads put a human inside an automated loop. Two
failure modes follow, and they pull in opposite directions.

If the human is asked too often, they learn to approve without reading. That is
**approval fatigue**, and it is worse than having no approval step at all,
because the operator now believes a control exists that in practice does not.

If the human is asked too rarely — or is asked but never notices — the agent
stalls, the task fails, and the operator's next move is to widen scopes and
lengthen lifetimes until the friction goes away. That also ends with no control.

So the design problem is not "how do we notify more loudly". It is **how do we
make each prompt rare enough to be worth reading, and make the waiting agent
behave sanely while it waits.**

## Decision

### 1. Reduce the number of prompts before improving them

- **Task sessions.** The operator opens a window before starting work — a
  scope (path prefixes and/or tags) plus a duration. Reads inside the window
  and inside the scope are recorded but not interrupted. The window closes
  automatically; there is no implicit renewal.
- **Trust on first use, per token × item, within a window.** The first read of
  a given item by a given token asks; subsequent reads inside the same window
  do not.
- **Tiering.** `approval_required` defaults to on for 🔥 service accounts,
  ☁️ cloud root keys, and 📜 signing certificates; off for other classes, which
  are still scoped, expiring, quota-limited, and audited.
- **Pre-authorization.** The operator can approve named items ahead of a known
  task ("this afternoon's deploy, these three items, two hours").

### 2. A blocked read pends; it does not fail

When a read requires approval, or a token has expired but is within its
renewal window, the daemon creates an approval record and returns `202` with an
`approval_id` and a `Retry-After`, instead of `403`. The agent's correct
behavior is then unambiguous: wait and poll. See ADR 0006 for the shape of the
response the agent actually reads.

### 3. Escalation ladder

| Elapsed | Action |
| --- | --- |
| 0 s | OS notification with Approve/Deny actions, tray badge, Web UI badge |
| 20 s | Repeat notification, with sound |
| 60 s | External channel, if configured |
| 5 min | Auto-deny, recorded, agent receives a definite `approval_timeout` |

Every stage appends to the audit chain, so "the operator was asked and did not
respond" is itself a durable record. The agent is never left waiting forever.

### 4. External channels are outbound-only and never carry secrets

The daemon **initiates** the connection (for example, long-polling the Telegram
Bot API). No inbound port is opened, so §4.4's loopback-only posture in the
master plan is preserved.

Constraints:

- An external message contains the item's label, the requesting token's label,
  the stated reason, and approve/deny controls. **It never contains secret
  material**, and it never contains a link that would by itself release one —
  that would reintroduce exactly the bearer-URL problem ADR 0002 exists to
  prevent.
- Approval from an external channel is bound to a pre-configured chat/account
  identity, established once from the local UI.
- Items may be flagged **local-approval-only**, in which case the external
  channel can notify but not approve.

### 5. Expiry is announced before it happens

Every successful read carries `X-BSC-Token-Expires-In`. A ⏰ panel lists
upcoming expiries, and a local notification fires at 20% of remaining lifetime
or 10 minutes, whichever comes first. Renewal extends an existing token rather
than issuing a new value, so agent configuration never changes.

### 6. Default parameters

These are **starting defaults chosen for this ADR, not measured values.** They
are configurable and expected to be tuned once the system is in real use.

| Parameter | Default | Bound |
| --- | --- | --- |
| Task session window | 30 min | max 8 h |
| Agent token TTL | 24 h | max 30 days |
| Renewal window | final 25% of token life | not after expiry + 5 min |
| Approval wait before auto-deny | 5 min | max 30 min |
| Escalation steps | 0 s / 20 s / 60 s | configurable |
| Expiry pre-warning | 20% remaining or 10 min | — |
| Handoff link | 60 s, single use | not extendable |

## Consequences

- A typical task interrupts the operator zero to two times rather than once per
  read, which is what makes the remaining prompts worth reading.
- An operator who is away turns into a hard five-minute deadline for the agent.
  This is deliberate: a stalled task is recoverable, an unattended release of a
  production key is not.
- Task sessions are a genuine widening of authority for their duration. They
  are scoped, time-boxed, non-renewing, and every read inside one is still
  recorded — but the window itself is the thing to review when something goes
  wrong.
- The external channel is optional. Without it, the ladder stops at the local
  notification and the auto-deny still applies.
- Approval fatigue is now a named threat with a named mitigation, and any future
  change that increases prompt frequency has to argue against this ADR.
