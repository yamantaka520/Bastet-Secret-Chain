# API and MCP Contract — v1 draft

**Status:** draft for M2, 2026-09-03. Not implemented. This document fixes the
*shape* of the daemon's HTTP API and MCP tool surface before code exists, so
that the two cannot drift apart (ADR 0006). Where this file and the master plan
disagree, the master plan wins and this file is wrong.

Authority chain: [`MASTER_PLAN.md`](MASTER_PLAN.md) → this contract →
implementation. Tests in M2 assert against this file.

## 0. Invariants every endpoint obeys

1. **A URL never carries authority.** Item references (`sref_…`) are opaque
   identifiers; possession grants nothing. Every value-releasing call needs a
   bearer token in the `Authorization` header (ADR 0002).
2. **No value without a ledger record.** The audit append happens before the
   response body is built. If the append fails, the request fails.
3. **No value without a reason.** `reason` is a required string on every path
   that can release a value. Empty or whitespace-only is a `400`.
4. **Errors are prose for a model, plus a code for a program.** Every error
   body has `error`, `next_action`, and `do_not`. See §4.
5. **Loopback by default.** The daemon listens on `127.0.0.1:8787` unless the
   operator has completed the remote-exposure gate in the master plan §4.4.
6. **Read-only agent surface.** No token, regardless of scope, can create,
   modify, or delete an item. Writes are a human-session-only API.

## 1. Identifiers and tokens

| Prefix | Meaning | Format |
| --- | --- | --- |
| `sref_` | Stable item reference, shown in UI, safe to paste anywhere | `sref_` + 22 base64url chars (128 bits) |
| `bsct_` | Agent bearer token **value** — the secret, shown once at mint | `bsct_` + 43 base64url chars (256 bits) |
| `tok_` | Token **id** — safe to log, appears in the ledger | `tok_` + 16 hex |
| `apr_` | Approval request id | `apr_` + 16 hex |
| `ses_` | Task session id | `ses_` + 16 hex |

The daemon stores only a hash of `bsct_` values. A token has:

```
id, label, scope { paths: [prefix…], tags: [tag…] }, read_only: true,
expires_at, renewable_until, max_reads, reads_used, rate_limit_per_min,
created_by, revoked_at
```

Scope matching: an item is in scope if its path starts with any `paths` prefix
**or** it carries any `tags` entry. An empty scope matches nothing.

## 2. HTTP API

Base path `/v1`. JSON request and response bodies, UTF-8. All timestamps are
RFC 3339 UTC. Every response carries `X-BSC-Request-Id`.

### 2.1 Agent surface — `Authorization: Bearer bsct_…`

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/secrets` | List in-scope items — **metadata only**, never values |
| `GET` | `/v1/secrets/{sref}` | Release the current version's value |
| `GET` | `/v1/secrets/{sref}/versions/{n}` | Release a specific version |
| `POST` | `/v1/access-requests` | Ask for approval explicitly |
| `GET` | `/v1/access-requests/{apr}` | Poll an approval |
| `POST` | `/v1/token/renew` | Extend the calling token inside its renewal window |
| `GET` | `/v1/token` | Inspect the calling token: scope, expiry, quota — never the value |

`GET /v1/secrets/{sref}` requires `?reason=` or a `X-BSC-Reason` header;
`POST` bodies carry `reason` as a field.

Successful release:

```http
HTTP/1.1 200 OK
X-BSC-Token-Expires-In: 3540
X-BSC-Reads-Remaining: 17
Cache-Control: no-store
Content-Type: application/json

{
  "sref": "sref_7Qn4…",
  "version": 3,
  "type": "cloud_key",
  "value": "<the secret>",
  "expires_at": "2026-10-01T00:00:00Z",
  "warning": null
}
```

`warning` is non-null when the token has ≤ 20% of its life or ≤ 10 minutes
left: `"token expires in 4m; call POST /v1/token/renew at a natural boundary"`.

Blocked release (approval required, or token expired but renewable):

```http
HTTP/1.1 202 Accepted
Retry-After: 5
Location: /v1/access-requests/apr_3f9…

{
  "status": "approval_pending",
  "approval_id": "apr_3f9…",
  "expires_at": "2026-09-03T14:07:11Z",
  "next_action": "Poll GET /v1/access-requests/apr_3f9… every 5 seconds until status is approved, denied, or timeout. A human has been notified.",
  "do_not": "Do not ask the user to paste the secret into the conversation. Do not retry the original request in a loop. Do not use a different token."
}
```

Approval poll states: `pending` → `approved` (body includes the value, once,
then the request is consumed) | `denied` | `timeout`.

### 2.2 Human surface — session cookie, loopback only

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/vault/unseal` | Passphrase → unseal |
| `POST` | `/v1/vault/seal` | Drop the KEK |
| `GET` | `/v1/vault/status` | sealed/unsealed, item count, chain head, uptime |
| `GET` `POST` | `/v1/items` | List / create |
| `GET` `PATCH` | `/v1/items/{sref}` | Detail / metadata edit |
| `POST` | `/v1/items/{sref}/versions` | Add a version (rotate) |
| `GET` | `/v1/items/{sref}/reveal` | Human reveal — re-auth for approval-required items |
| `GET` `POST` | `/v1/tokens` | List / mint (value returned exactly once) |
| `DELETE` | `/v1/tokens/{tok}` | Revoke |
| `GET` `POST` | `/v1/sessions` | List / open a task session `{scope, duration}` |
| `DELETE` | `/v1/sessions/{ses}` | End early |
| `GET` | `/v1/approvals` | Inbox |
| `POST` | `/v1/approvals/{apr}/approve` · `/deny` | Decide |
| `GET` | `/v1/audit?from=&limit=` | Ledger records |
| `GET` | `/v1/audit/verify` | Recompute the chain |
| `POST` | `/v1/handoff-links` | Mint a single-use 60 s link — **off by default**, `403` unless enabled |

Human-surface responses never include `value` except on `/reveal`, which
carries `Cache-Control: no-store` and is itself a `secret_read` ledger entry.

### 2.3 Ledger actions this API produces

`vault_created` `unseal` `seal` `item_created` `version_added` `secret_read`
`search` `token_minted` `token_renewed` `token_revoked` `session_opened`
`session_closed` `approval_requested` `approval_notified` `approval_escalated`
`approval_decided` `approval_timeout` `handoff_minted` `handoff_used`
`exposure_acknowledged`. Each carries `actor`, optional `subject`, `outcome`
∈ {`ok`,`denied`,`error`,`timeout`}, and a `meta` JSON object that **never**
contains a value, a token value, or a passphrase.

## 3. MCP surface

Served by `bsc mcp` over stdio. The MCP server holds one `bsct_` token from its
configuration and calls the HTTP API; it has no other authority. Tool
descriptions are security-relevant text and are reviewed as such.

| Tool | Input | Output | Notes |
| --- | --- | --- | --- |
| `list_secrets` | `{ path?: string, tag?: string }` | `[{ sref, name, path, type, tags, env, expires_at, approval_required }]` | Never a value. Names are decrypted server-side; the token must be in scope |
| `get_secret` | `{ sref: string, reason: string }` | `{ value, version, type, expires_at, warning? }` **or** an `approval_pending` result | `reason` required |
| `request_access` | `{ sref: string, reason: string }` | `{ approval_id, expires_at }` | Explicit ask; use when `get_secret` returned `approval_pending` and the agent wants a handle |
| `check_access` | `{ approval_id: string, wait_seconds?: number ≤ 60 }` | `{ status, value? }` | Server-side blocking up to `wait_seconds`; value returned once |
| `renew_access` | `{}` | `{ expires_at, renewable_until }` | Never widens scope |

There is no write tool. If a future need arises it is a new ADR, not a new tool.

Canonical `get_secret` description (the text the model reads):

> Returns the current value of one stored credential. **This is a live secret.**
> Use it only for the immediate operation; do not write it to a file, do not
> repeat it in your reply, do not paste it into chat, do not log it. If the
> result is `approval_pending`, a human has been notified — wait with
> `check_access`; do not ask the user to paste the secret. `reason` is shown to
> the approving human and recorded permanently: say concretely what you are
> about to do with it.

MCP results are the same JSON as the HTTP responses in §2.1, so a test can
assert equality between the two paths for every code in §4.

## 4. Error contract

Every non-2xx body:

```json
{
  "error": "<code>",
  "message": "<one sentence, human>",
  "next_action": "<what the agent should do now>",
  "do_not": "<what the agent must not do>",
  "retry_after": 5,
  "ui": "http://127.0.0.1:8787/#/…",
  "request_id": "…"
}
```

| Code | HTTP | `next_action` | `do_not` |
| --- | --- | --- | --- |
| `token_expired` | 401 | Call `renew_access` / `POST /v1/token/renew`. If refused, `request_access` with a reason. | Do not ask the user to paste the secret. Do not substitute another token. |
| `token_revoked` | 401 | Stop. Tell the user this token was revoked and needs re-issuing in the vault UI. | Do not retry. Do not look for another credential source. |
| `scope_mismatch` | 403 | Tell the user this token does not cover the item; they can widen scope or mint another. | Do not try other srefs to find one that works. |
| `approval_pending` | 202 | Poll `check_access` until decided. | Do not repeat the original request in a loop. |
| `approval_denied` | 403 | Stop this step. Report the denial to the user with the reason you gave. | Do not re-request with a different reason. |
| `approval_timeout` | 408 | The human did not respond in time. Report it and stop, or ask the user to approve in the UI and retry once. | Do not loop. |
| `quota_exhausted` | 429 | This token's read budget is spent. Tell the user. | Do not retry. |
| `rate_limited` | 429 | Wait `retry_after` seconds. | Do not tighten the loop. |
| `vault_sealed` | 503 | The vault is locked; the human must unseal it in the UI. | Do not ask the user for the vault passphrase — it is entered in the UI, never in chat. |
| `not_found` | 404 | Check the sref with `list_secrets`. | Do not guess srefs. |
| `reason_required` | 400 | Repeat the call with a concrete `reason`. | Do not use a placeholder reason. |
| `invalid_request` | 400 | Fix the request per `message`. | — |
| `handoff_disabled` | 403 | Handoff links are off. Use a token. | — |

The `do_not` column is the single most important text in this document. It is
the difference between an agent that waits and an agent that asks the user to
paste an AWS key into a chat window.

## 5. Renewal semantics

- A token may be renewed when `now ≥ expires_at − 25 % × lifetime` and
  `now ≤ renewable_until` (default `expires_at + 5 min`).
- Renewal sets `expires_at += original_lifetime`, capped by the token's
  `max_lifetime` (default 30 days from mint). Scope, `max_reads`, and
  `rate_limit` are unchanged. The token **value** is unchanged.
- A renewed token is a `token_renewed` ledger record with the new `expires_at`.
- Renewal past `renewable_until` returns `token_expired` with
  `renewable: false`; the only recovery is a human minting a new token.

## 6. Task sessions

`POST /v1/sessions { scope: { paths, tags }, duration_seconds }` → `ses_…`.
While a session is open, a read whose item is inside **both** the token's scope
and the session's scope, and whose item is not `local-approval-only`, is
recorded and released without an approval prompt. Sessions never renew; the
UI shows a countdown; `DELETE` ends one early. `duration_seconds` ≤ 28 800.

## 7. Versioning of this contract

`/v1` is stable once M2 ships. Additive fields are allowed at any time; a
removed field, a changed code, or a changed `do_not` text is `/v2`. The MCP
tool names and input schemas follow the same rule.

## 8. What this contract deliberately does not do

- No secret in a URL, query string, or path — ever, including `/reveal`.
- No agent write path.
- No batch "give me everything in scope" endpoint. `list_secrets` returns
  metadata; values are one call each, one ledger record each.
- No long-lived server-side "remember this agent" state beyond the token
  itself and open task sessions.
