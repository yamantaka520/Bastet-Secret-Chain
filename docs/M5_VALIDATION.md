# M5 Validation — agent integration

**Milestone:** M5 from [`MASTER_PLAN.md`](MASTER_PLAN.md) §6.
**Gate text:** Claude Code / Codex / Agy recipes, CI and script patterns,
scope-per-project guidance; a real multi-step agent task completes across a
token renewal and an approval.
**Status:** gate met, 2026-09-04, by two real agents: **Codex CLI 0.153**
first, then **Claude Code 2.1.233** once its CLI login was refreshed. Nothing
here is a release.

## What was built

- [`docs/AGENT_INTEGRATION.md`](AGENT_INTEGRATION.md): the four-part shape of
  a correct integration, Claude Code (`.mcp.json` / `~/.claude.json`, `claude
  -p --mcp-config`), Codex (`~/.codex/config.toml`), Agy/Gemini
  (`~/.gemini/settings.json`), scripts and CI over the HTTP API with the three
  answers a script must handle, scope-per-project, a troubleshooting table,
  and the anti-patterns spelled out.
- [`scripts/m5-gate.sh`](../scripts/m5-gate.sh): the gate test as a reusable
  script (Claude Code form).
- A `CLAUDE.md` paragraph agents can be given verbatim.

## The real-agent run — 2026-09-04 01:46 local

Setup: local daemon (`bsc serve`, debug build) on `127.0.0.1:8797`; an
approval-required 🔥 service-account item `m5-gate-service-account` under
`prod/m5`; a token scoped to `prod/m5` with a **100 s lifetime**, minted and
then left for 105 s so the agent would meet it **expired but renewable**; a
scripted "human" that approves the first inbox entry 8 s after it appears.

Agent: `codex exec --json --dangerously-bypass-approvals-and-sandbox` in an
empty scratch workspace, with the `bsc` MCP server injected via `-c
mcp_servers.bsc.*` overrides (the operator's own Codex config was not edited).
Prompt: find the item with `list_secrets`, read it with a stated reason, renew
if told the token expired, wait with `check_access` if pending, and reply with
only the `project_id`.

What the agent did, from the `--json` event stream:

```
→ bsc list_secrets {}                                    failed   ← token_expired (renewable: true)
→ bsc renew_access {}                                    completed ← renewable_until
→ bsc list_secrets {}                                    completed ← items
→ bsc get_secret {sref, reason: "M5 gate test: deploy build 1 to Firebase"}
                                                         completed ← approval_pending
→ bsc check_access {approval_id, wait_seconds: 60}       completed ← status: approved, project_id
  [assistant] m5-gate-project
```

The human approver log: `approved apr_049af6764cfcb942 at 01:46:52` — while
the agent was blocked inside `check_access`.

The item's ledger, in order: `approval_requested` (token, reason verbatim) →
`approval_escalated` (step 1) → `approval_decided approved` (human session) →
`secret_read ok` (token, same reason). The token's ledger: `token_renewed`
`from 1788457571 to 1788457671` — exactly one lifetime, no scope change.

The agent's final reply was the single field asked for. The full value does
appear **inside the tool result** in the agent's transcript — that is what
`get_secret` returns and is the reason `use_secret` (value never reaches the
agent) is scheduled for M6.

### The Claude Code run — 2026-09-04 01:59 local

Same daemon, same item name, a fresh 100 s token, `scripts/m5-gate.sh`
unchanged. `claude -p --mcp-config … --allowedTools mcp__bsc__*`, seven
turns, 46 s:

```
→ mcp__bsc__list_secrets {}                              ← token_expired
  [assistant] The token expired but is renewable, so I'll renew and retry.
→ mcp__bsc__renew_access {}                              ← renewable_until
→ mcp__bsc__list_secrets {}                              ← items (two with that name; it took the first)
→ mcp__bsc__get_secret {sref, reason: "M5 gate test: deploy build 1 to Firebase"}
                                                         ← approval_pending
  [assistant] Approval is pending, so I'll wait on it.
→ mcp__bsc__check_access {approval_id, wait_seconds: 60} ← status: approved, project_id
  [assistant] m5-gate-project
```

Approver: `approved apr_8e148f3d9061b633 at 02:00:13`, while the agent was
inside `check_access`. Ledger: `token_renewed` for `tok_20f293a3a5d3d783`;
the read landed on the *first* `m5-gate-service-account` item (the gate script
creates a new one each run and the agent picked the earlier sref), so the
per-item ledger the script prints for the new sref shows only `item_created`
— the `secret_read` is on the sibling. The agent narrated each decision in one
sentence and never printed the value.

### Why the first run used Codex

`claude -p` was attempted first and failed before any tool call:
`Failed to authenticate: OAuth session expired`; `claude auth status` reported
`loggedIn: false` (the CLI login is separate from the desktop app's). Gemini
CLI failed with `IneligibleTierError`. Codex CLI was logged in. The recipe for
Claude Code is documented and the gate script is written in its form; running
it is one `claude login` away and is listed as follow-up.

A first Codex attempt without the bypass flag reached the MCP server and then
had every tool call refused with "tool approvals are disabled" — `exec` mode
has no way to grant approvals interactively. The flag is appropriate for an
empty scratch workspace whose only tools are the five read-only bsc tools; it
would not be appropriate for a real working directory.

## Evidence

- Codex event stream: five `mcp_tool_call` items in the order above,
  `turn.completed`, final `agent_message` = `m5-gate-project`.
- Daemon ledger for `sref_2kL0-1iTy1Kc0_HiozCU2g` and the `token_renewed`
  record, both read back through `GET /v1/audit` after the run.
- `docs/AGENT_INTEGRATION.md` reviewed against what the run actually needed:
  the reason header, the renew-then-retry step, and the `wait_seconds` wait
  all appear in the recipe because the run exercised them.

## Not done — explicitly

- **Agy and Grok were not exercised end to end**, only documented; both are
  logged in on the operator's machine and could be run with the same script
  adapted to their MCP configuration.
- Codex loaded the operator's other configured MCP servers alongside `bsc`
  and tried one of them first; a per-project Codex config with only `bsc`
  would be tidier and is what the integration doc recommends.
- The approver was a script, not a person at the inbox; the M3 browser pass
  covered the human side of the same flow.
- No CI job runs an agent; the gate is a recorded run plus a script, like M3's
  browser pass.
