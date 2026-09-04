# AI agent guide

**Applies to:** Bastet Secret Chain 0.2.0
**Languages:** [繁體中文](../zh-Hant/agents.md) · [简体中文](../zh-Hans/agents.md) · **English** · [日本語](../ja/agents.md) · [한국어](../ko/agents.md)
**See also:** [Installation](install.md) · [User guide](guide.md) · [API contract](../../API_CONTRACT.md)

This is the point of the project: an agent fetches exactly the secret it needs,
at the moment it needs it, and the secret never appears in a prompt, a URL, a
shell history or a transcript.

---

## 1. What a correct integration looks like

1. A **human** mints a scoped, expiring token in the UI and puts it in the
   agent's **configuration file** — never in a prompt, a repository or a URL.
2. The agent reaches the vault as an **MCP server**, not through `curl`.
3. The agent's instructions tell it to give a real reason, to wait when a read
   is pending, and never to ask a person to paste a secret.
4. A human sees every read in the ledger, and every high-value read in the
   inbox first.

If one of those four is missing, the integration is wrong even when it works.

Why MCP rather than raw HTTP: the tool description is a specification the model
actually reads, the value never passes through a shell, and the token never
appears in a command the agent generates. The HTTP API remains the single
source of truth and the only audit entry point, for CI and anything that does
not speak MCP.

---

## 2. Connecting an agent

The MCP server is the same binary: `bsc mcp` talks to a running daemon over
stdio. Give it a URL and a token from the environment or a `0600` file.

**Claude Code** — `.mcp.json` in the project (committed **without** the token)
or `~/.claude.json`:

```json
{
  "mcpServers": {
    "bsc": {
      "command": "bsc",
      "args": ["mcp", "--url", "http://127.0.0.1:8787"],
      "env": { "BSC_TOKEN": "${BSC_TOKEN}" }
    }
  }
}
```

**Codex CLI** — `~/.codex/config.toml`:

```toml
[mcp_servers.bsc]
command = "bsc"
args = ["mcp", "--url", "http://127.0.0.1:8787", "--token-file", "/home/you/.bsc/tokens/codex"]
```

**Gemini CLI / Agy** — `~/.gemini/settings.json`:

```json
{ "mcpServers": { "bsc": { "command": "bsc", "args": ["mcp"], "env": { "BSC_TOKEN": "$BSC_TOKEN" } } } }
```

For a remote vault use `"--url", "https://secrets.example.com"`. Keep one
server entry per project, each with its own narrowly scoped token: an agent
working on project A then cannot even list project B's items.

---

## 3. The six tools

All read-only. There is no tool that creates, edits or deletes anything — that
is a human action in the UI.

| Tool | Input | Result |
| --- | --- | --- |
| `list_secrets` | `path?`, `tag?` | In-scope items: reference, name, path, type, tags, expiry, whether approval is required. **Never a value.** |
| `get_secret` | `sref`, `reason` | The value, its version and any warning — or `approval_pending`. |
| `request_access` | `sref`, `reason` | An approval id to wait on. |
| `check_access` | `approval_id`, `wait_seconds?` (≤ 60) | The decision, and the value once when approved. |
| `use_secret` | `sref`, `reason`, `url`, `method?`, `headers?`, `body?` | The upstream service's answer. The credential is injected by the daemon and never reaches the agent. |
| `renew_access` | — | A later expiry for the calling token. Never widens scope. |

`reason` is required and is recorded in the ledger. "deploy staging from commit
abc123" is a reason; "task" is not.

---

## 4. What to tell the agent

Put this in `CLAUDE.md`, `AGENTS.md` or the equivalent, as is:

> Credentials come from the `bsc` MCP server. Find the item with
> `list_secrets`, then call `get_secret` with a `reason` that states what you
> are about to do. The value is live: never write it to a file, print it, echo
> it into a shell command, or repeat it in your reply. If a call returns
> `approval_pending`, call `check_access` with `wait_seconds: 60` and keep
> waiting — do not ask me to paste the secret and do not retry the original
> call in a loop. If a result carries a token-expiry warning, call
> `renew_access` at the next natural boundary. If an item has a use binding,
> prefer `use_secret` over reading the value.

The single most important sentence is the one that tells the agent **not** to
ask a person to paste a secret. That is the failure mode this whole design
exists to prevent.

---

## 5. Scripts and CI

Where there is no MCP client, call the HTTP API. The token lives in the CI
secret store; the reason goes in a header, never in the URL:

```sh
curl -fsS -H "Authorization: Bearer $BSC_TOKEN" \
     -H "X-BSC-Reason: deploy $GITHUB_SHA to staging" \
     "$BSC_URL/v1/secrets/$SREF" | jq -r .value
```

Handle three answers:

- `200` — the value is in `.value` (or `.value_base64` for binary).
- `202 approval_pending` — poll the approval until decided, respecting
  `Retry-After`; log clearly and stop on `denied` or `timeout`.
- `401 token_expired` with `renewable: true` — `POST /v1/token/renew`, then
  retry once.

Anything else is a hard failure. Print the `next_action` from the body; it is
written to be read by whoever is looking at the log.

Use a per-pipeline token with a read quota sized to the job and a lifetime no
longer than its schedule. Rotate by minting a new one and revoking the old.

---

## 6. Error codes

Every error carries a machine-readable `error`, a human `message`, a
`next_action`, and a `do_not`. The last one exists because an agent that
receives an undifferentiated `401` improvises, and its worst improvisation is
asking a person to paste a credential into a chat window.

| Code | HTTP | The agent should |
| --- | --- | --- |
| `approval_pending` | 202 | Wait with `check_access`. Not retry in a loop. |
| `approval_denied` | 403 | Stop and report. Not re-ask with a different reason. |
| `approval_timeout` | 408 | Report that nobody answered. Not loop. |
| `token_expired` | 401 | Renew, then retry once. Not ask for a pasted secret. |
| `token_revoked` | 401 | Stop and tell the user to re-issue. Not look elsewhere. |
| `scope_mismatch` | 403 | Say what it needs. Not probe other references. |
| `quota_exhausted` | 429 | Stop and tell the user. |
| `rate_limited` | 429 | Wait `retry_after`. Not tighten the loop. |
| `vault_sealed` | 503 | Say a human must unseal in the UI. **Never** ask for the vault passphrase. |
| `not_found` | 404 | Re-check with `list_secrets`. Not guess references. |
| `reason_required` | 400 | Repeat with a concrete reason. Not a placeholder. |
| `use_not_configured` | 400 | Ask a human to bind the item, or read the value if it genuinely needs it. |
| `use_not_allowed` | 403 | Say what URL it needs. Not probe other URLs. |
| `upstream_failed` | 502 | Retry once, then report. Not ask for the secret to call the service itself. |

---

## 7. When something is wrong

| The agent says | It means | Do |
| --- | --- | --- |
| "unauthorized" | The token is not recognized | Check `BSC_TOKEN`, `--token-file`, and the URL |
| "token_expired, renewable: false" | Past the renewal window | Mint a new token in the UI |
| "scope_mismatch" | Right vault, wrong token | Widen the scope or mint one for that path |
| "approval_pending" for a long time | Nobody approved | Open the inbox; consider a task session next time |
| "vault_sealed" | The daemon restarted | Unseal in the UI. The agent must never learn the passphrase |
| It asks you to paste the secret | It ignored its instructions | Refuse. Check it is really using `bsc mcp` and not a shell tool |

---

## 8. Anti-patterns

- A `bsct_…` token in a prompt, a `CLAUDE.md`, a committed `.env`, or a URL.
  A token is a credential; treat it like one.
- One broad token shared by every agent. Scope is what makes the ledger worth
  reading.
- Letting an agent `curl` the API from a shell tool when MCP is available: the
  value lands in process arguments and shell history.
- Turning off approval on a service account to quieten a pipeline. Open a task
  session or pre-authorize instead; both end by themselves.
- Pasting a secret "just this once" to unblock a run. That is the exact event
  this system is built to make unnecessary.
