# Agent integration

**Status:** current as of 0.2.0, 2026-09-04. Step-by-step manuals in five
languages: [`docs/manual/`](manual/) — this file is the per-client reference. How an agent reaches the vault, in order of
preference, and what to tell it. The MCP server is the default (ADR 0006); the
HTTP API is for scripts, CI, and anything that does not speak MCP.

## 0. The shape of a correct integration

1. A human mints a **scoped, expiring token** in the UI (or `POST /v1/tokens`)
   and puts it in the agent's **configuration** — never in a prompt, a
   transcript, a repository, or a URL.
2. The agent gets the vault as an **MCP server** with six read-only tools.
3. The agent's instructions say: *use `list_secrets` to find the sref, call
   `get_secret` with a concrete `reason`, never write the value to a file or
   repeat it, and if the result is `approval_pending` wait with
   `check_access` — do not ask the user to paste anything.*
4. A human sees every read in the ledger and every high-value read in the
   inbox first.

If any of those four is missing, the integration is wrong even if it works.

## 1. Claude Code

Project-scoped (`.mcp.json` in the repository, committed **without** the
token) or user-scoped (`~/.claude.json`). The token comes from the
environment so the file can be shared:

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

Set `BSC_TOKEN` in the shell that launches Claude Code, or point at a file:
`"args": ["mcp", "--token-file", "/Users/you/.bsc/tokens/claude-code"]` with
that file `0600`. Against the deployed instance use
`"--url", "https://secrets.example.com"`.

Non-interactive runs (the pattern the M5 gate test uses):

```sh
claude -p "Read the staging database URL from the vault and print only its host" \
  --mcp-config .mcp.json --allowedTools "mcp__bsc__*" --output-format text
```

`CLAUDE.md` guidance that keeps the agent honest — copy it as is:

> Credentials come from the `bsc` MCP server. Find the item with
> `list_secrets`, then `get_secret` with a `reason` that says what you are
> about to do. The value is live: do not write it to a file, print it, or
> repeat it. If you get `approval_pending`, call `check_access` with
> `wait_seconds: 60` and keep waiting; do not ask me to paste the secret. If
> a result carries a token-expiry `warning`, call `renew_access` at the next
> natural boundary.

## 2. Codex CLI

`~/.codex/config.toml`:

```toml
[mcp_servers.bsc]
command = "bsc"
args = ["mcp", "--url", "http://127.0.0.1:8787"]
env = { BSC_TOKEN = "bsct_…" }   # or use --token-file and keep the file 0600
```

Codex reads MCP tool descriptions the same way; the `get_secret` description
already carries the live-secret and no-paste text. Put the same paragraph as
above in `AGENTS.md`.

## 3. Agy / Gemini CLI

`~/.gemini/settings.json` (Agy uses the same shape):

```json
{ "mcpServers": { "bsc": { "command": "bsc", "args": ["mcp"], "env": { "BSC_TOKEN": "$BSC_TOKEN" } } } }
```

## 4. Scripts and CI — the HTTP API

When there is no MCP client, call the API directly. Keep the token in the CI
secret store and the **reason in a header**, never the URL:

```sh
# GitHub Actions: secrets.BSC_TOKEN; the runner must be able to reach the daemon.
curl -fsS -H "Authorization: Bearer $BSC_TOKEN" \
     -H "X-BSC-Reason: deploy $GITHUB_SHA to staging" \
     "$BSC_URL/v1/secrets/$SREF" | jq -r .value
```

Handle the three answers a script will meet: `200` (value in `.value` or
`.value_base64`), `202 approval_pending` (poll `Location` until `approved`,
respecting `Retry-After`; give up on `denied`/`timeout` with a clear log
line), and `401 token_expired` with `renewable: true` (`POST /v1/token/renew`,
then retry once). Everything else is a hard failure; print the `next_action`
from the body — it is written to be read.

Use a **per-pipeline token** with `max_reads` sized to the job and a
`lifetime` no longer than the job's schedule. Rotate by minting a new one and
revoking the old; the ledger shows which pipeline read what.

## 5. Scope-per-project

One MCP server entry per project, each with its own token whose scope is that
project's path prefix (`prod/mobile`, `staging/web`). An agent working in
project A then cannot even list project B's items, and the ledger attributes
every read to the right token label.

## 6. What to do when it goes wrong

| The agent says… | It means | Do |
| --- | --- | --- |
| "unauthorized" | the token is not recognized | check `BSC_TOKEN`, `--token-file`, the URL |
| "token_expired, renewable: false" | past the grace window | mint a new token in the UI |
| "scope_mismatch" | right vault, wrong token | widen scope or mint one for that path |
| "approval_pending" for a long time | nobody approved | open the inbox at `/#/approvals` |
| "vault_sealed" | the daemon restarted | unseal in the UI; the agent must not be told the passphrase |
| asks you to paste the secret | the agent ignored its instructions | refuse; check that the MCP server is `bsc mcp`, not a raw HTTP tool |

## 7. Anti-patterns, spelled out

- Putting `bsct_…` in a prompt, a `CLAUDE.md`, a `.env` committed to git, or a
  URL. The token is a credential; treat it like one.
- Giving one broad token to every agent. Scope is what makes the ledger
  useful.
- Letting the agent read secrets through `curl` in a shell tool when MCP is
  available: the value lands in process arguments and shell history.
- Turning off `approval_required` on service accounts and signing keys to make
  a pipeline quieter. Open a task session instead; it ends by itself.
