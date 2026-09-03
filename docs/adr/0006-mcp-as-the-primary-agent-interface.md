# ADR 0006 — MCP is the primary agent interface; the HTTP API is the sole truth

- **Status:** accepted, 2026-09-03
- **Deciders:** project owner
- **Related:** [ADR 0002](0002-reference-urls-are-not-credentials.md), [ADR 0005](0005-approval-and-reminder-model.md)

## Context

The consumer of this vault is an LLM agent, not a program. That changes what a
good interface is.

A program that receives `401` retries or fails. An agent that receives `401`
**improvises**: it retries with a different value, invents a plausible key, or —
the worst case — asks the human to paste the secret into the conversation. That
last behavior writes the credential into a transcript that is stored and often
uploaded, which is precisely the outcome ADR 0002 exists to prevent. The
interface therefore has to be designed for a reader that will act on prose.

Two delivery shapes were considered: a plain HTTP API that agents call with
`curl` or an SDK, and a Model Context Protocol server.

## Decision

**The HTTP API is the single source of truth and the single audit entry point.
The MCP server is a thin wrapper over it, shipped inside the same binary
(`bsc mcp`), and it bypasses no check.** MCP is the interface agents should
use by default.

### Why MCP is the default

1. A tool description is a **specification field aimed at the model**. It can
   state "this returns a live credential; do not write it to a file, do not
   repeat it in your reply, do not paste it into chat" at the point of use. A
   plain API has no such field, so the same instruction has to live in a system
   prompt, where it competes for attention and is eventually compacted away.
2. **The secret never passes through a shell.** `curl` puts values in process
   arguments and shell history; MCP carries them over stdio/JSON-RPC inside the
   tool result.
3. The token lives in the MCP server's configuration, so it **never appears in
   a command the agent generates**.
4. Expiry, pending approval, and denial become structured tool results, which
   agents already handle well.
5. Scope binds naturally to a server instance: one project, one MCP server, one
   narrowly-scoped token.

### Why the HTTP API remains

CI jobs, deployment scripts, non-MCP agents, and the operator's own tooling need
it; the MCP server is itself a client of the same internal service; and being
able to reproduce a failure with `curl` is worth keeping.

### Tool surface

```
list_secrets(path?, tag?)     → metadata only, never a value
get_secret(sref, reason)      → the value; reason is required
request_access(sref, reason)  → explicit approval request, returns approval_id
check_access(approval_id)     → resolves to approved / denied / timeout
renew_access()                → extends the current token, never widens scope
```

There is deliberately **no `create_secret` or `delete_secret`.** Writing is
something a human does in the Web UI. The agent surface is read-only.

`reason` is mandatory on every path that can release a value. It is written into
the audit chain and shown in the approval prompt. Beyond the audit value, a
manipulated agent's stated reason is frequently where the manipulation becomes
visible to a human.

### Errors are written for the model

Every failure returns a machine-readable code *and* prose the agent will act on,
including an explicit prohibition:

```json
{
  "error": "token_expired",
  "expired_at": "2026-09-03T14:02:11Z",
  "renewable": true,
  "next_action": "Call renew_access. If that fails, call request_access with a reason; a human will approve within 5 minutes.",
  "retry_after": 5,
  "do_not": "Do not ask the user to paste the secret into the conversation. Do not substitute another token. Do not continue without the credential."
}
```

Codes are distinguishable — `token_expired`, `scope_mismatch`,
`approval_pending`, `approval_timeout`, `approval_denied`, `quota_exhausted`,
`vault_sealed` — each with a deep link into the UI. An interface that answers
every failure with an undifferentiated `401` forces both the agent and the
operator to guess, and guessing is how this control gets abandoned.

### Planned complement: never hand over the value

For the common case where an agent needs a credential only in order to call
something with it, a `use_secret` tool and a `bsc exec` subcommand will let the
daemon inject the value into a child process environment, or proxy the outbound
call itself, so the agent never observes the credential. This does not replace
`get_secret`, which remains necessary when the agent must handle the value.
This resolves the direction of master plan open question 4; the implementation
is scheduled for M6.

## Consequences

- **The MCP server moves from M5 to the end of M2.** If MCP is the primary
  interface, building it late would let the HTTP API's shape drift into
  something awkward to wrap.
- Two interfaces exist, but only one implementation of authorization, quota,
  approval, and audit. Any check reachable only through one of them is a bug.
- Agents need configuration rather than a pasted URL. That friction is the
  product working as intended.
- Tool descriptions become security-relevant text and must be reviewed as such.
