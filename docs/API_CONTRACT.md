# API and MCP Contract — v1 draft

**Status:** v1 as implemented in M2, 2026-09-03. This document fixes the
*shape* of the daemon's HTTP API and MCP tool surface so that the two cannot
drift apart (ADR 0006); `bsc-mcp/tests/parity.rs` asserts they return identical
JSON and `bsc-daemon/tests/api.rs` asserts every code below is reachable with
this shape. Where this file and the master plan disagree, the master plan wins
and this file is wrong.

**Revisions during implementation (2026-09-03):** an expired-but-renewable
token is `401 token_expired` with `renewable: true`, not `202` — the agent can
self-serve, so nothing is pending on a human. `/reveal` is `POST` with an
optional passphrase, never `GET`. Task sessions cover `local-approval-only`
items too (they are opened from the local UI; the flag restricts *external*
approval per ADR 0005 §4). The item id **is** the `sref`; there is no separate
reference table. Human-surface codes and the same-origin rule were added.

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
| `sref_` | Stable item reference **and** the item's id, shown in UI, safe to paste anywhere | `sref_` + 22 base64url chars (128 bits) |
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
| `POST` | `/v1/secrets/{sref}/use` | **Use without seeing**: the daemon sends one https request with the credential injected per the item's binding; body `{ reason, url, method?, headers?, body? }`; answers `{ upstream_status, upstream_headers, body\|body_base64, truncated }` |
| `POST` | `/v1/access-requests` | Ask for approval explicitly |
| `GET` | `/v1/access-requests/{apr}` | Poll an approval |
| `POST` | `/v1/token/renew` | Extend the calling token inside its renewal window |
| `GET` | `/v1/token` | Inspect the calling token: scope, expiry, quota — never the value |

`GET /v1/secrets/{sref}` requires `?reason=` or an `X-BSC-Reason` header
(prefer the header — it keeps the reason out of URLs and access logs; the MCP
server always uses it); `POST` bodies carry `reason` as a field.

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

Blocked release (approval required — a human must act):

```http
HTTP/1.1 202 Accepted
Retry-After: 5
Location: /v1/access-requests/apr_3f9…

{
  "error": "approval_pending",
  "status": "approval_pending",
  "approval_id": "apr_3f9…",
  "expires_at": "2026-09-03T14:07:11Z",
  "next_action": "Poll GET /v1/access-requests/apr_3f9… every 5 seconds until status is approved, denied, or timeout. A human has been notified.",
  "do_not": "Do not ask the user to paste the secret into the conversation. Do not retry the original request in a loop. Do not use a different token."
}
```

Approval poll (`GET /v1/access-requests/{apr}`) answers `200` with
`status: pending` (and `Retry-After`) while waiting; `200` with
`status: approved` **plus the value body of §2.1, once** on approval; `200`
with `status: consumed` on later polls (the grant now lets `get_secret`
through); and the contract errors `approval_denied` (403) or `approval_timeout`
(408) otherwise. A poll for an approval that belongs to another token is
`not_found`.

An expired token that is still inside its renewal window is **not** blocked:
it gets `401 token_expired` with `renewable: true`, because the agent can
recover without a human by calling renew.

### 2.2 Human surface — session cookie, loopback only

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/vault/unseal` | Passphrase → unseal |
| `POST` | `/v1/vault/seal` | Drop the KEK |
| `GET` | `/v1/vault/status` | sealed/unsealed, item count, chain head, uptime |
| `GET` `POST` | `/v1/items` | List / create |
| `GET` `PATCH` | `/v1/items/{sref}` | Detail / metadata edit |
| `POST` | `/v1/items/{sref}/versions` | Add a version (rotate) |
| `PUT` | `/v1/items/{sref}/use` | Set or clear the use binding `{ binding: { urls: ["https://…/*"], header: "Authorization: Bearer {value}", methods: ["GET","POST"] } \| null }` |
| `POST` | `/v1/items/{sref}/reveal` | Human reveal; body `{ passphrase? }` — required for approval-required items |
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

**Authentication.** `POST /v1/vault/unseal { passphrase }` is also login: it
verifies the passphrase (unsealing if needed) and sets an `HttpOnly;
SameSite=Strict` cookie `bsc_session`. Sessions idle out after 15 minutes and
are all dropped on seal. Every other human route requires the cookie.

**Same-origin.** State-changing human calls must carry an `X-BSC-Client`
header (any value); its presence forces a CORS preflight that a foreign page
cannot pass. Any request with an `Origin` header that is not
`http://127.0.0.1:*`, `http://localhost:*`, or the single configured
`--public-origin` is refused with `forbidden_origin`. A `bsct_` token never
grants the human surface.

**Login throttle.** `POST /v1/vault/unseal` allows 5 failed attempts per
client per 10-minute window; further attempts return `429 rate_limited` with
`retry_after: 600` without running the KDF. The client key is the first
`X-Forwarded-For` hop when `--public-origin` is set, otherwise one shared
local bucket.

### 2.3 Ledger actions this API produces

`vault_created` `unseal` `login` `seal` `item_created` `item_updated`
`version_added` `secret_read` `search` `token_minted` `token_renewed`
`token_revoked` `secret_used` `session_opened` `session_closed` `approval_requested`
`approval_escalated` `approval_decided` `approval_timeout` and, once
implemented, `handoff_minted` `handoff_used` `exposure_acknowledged`.
`approval_escalated` carries `step`; the notification itself is the
daemon's `Notifier`, not a separate ledger action. Each carries `actor`, optional `subject`, `outcome`
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
| `use_secret` | `{ sref, reason, url, method?, headers?, body? }` | the daemon's `/use` response | The credential never enters the agent; URL and method must match the human-set binding; the credential header cannot be supplied or overridden by the agent |
| `renew_access` | `{}` | `{ expires_at, renewable_until }` | Never widens scope |

There is no write tool. If a future need arises it is a new ADR, not a new tool.

`use_secret` is the value-free delegation promised in ADR 0006 and master
plan open question 4, implemented 2026-09-04. Its guards, in order: token,
liveness, scope, approval (a use pends exactly like a read), the item's
binding (https-only URL patterns, methods), the SSRF guard (no private,
loopback, link-local, or metadata addresses; no redirects; 30 s; 1 MiB body),
and only then decryption. The ledger records `secret_used` with method, host,
and path — never the value, never the response.

Canonical `get_secret` description (the text the model reads):

> Returns the current value of one stored credential. **This is a live secret.**
> Use it only for the immediate operation; do not write it to a file, do not
> repeat it in your reply, do not paste it into chat, do not log it. If the
> result is `approval_pending`, a human has been notified — wait with
> `check_access`; do not ask the user to paste the secret. `reason` is shown to
> the approving human and recorded permanently: say concretely what you are
> about to do with it.

MCP results are the same JSON as the HTTP responses in §2.1, so a test can
assert equality between the two paths for every code in §4. Concretely, a
`tools/call` result is `{ content: [{ type: "text", text }], structuredContent,
isError }` where `structuredContent` is the daemon's body verbatim minus
`request_id`, `text` is the same JSON pretty-printed, and `isError` is true
for any 4xx/5xx — **but false for `202 approval_pending`**, which is a wait,
not a failure. Two codes originate in the MCP server itself, with the same
shape: `daemon_unreachable` (the daemon is down; `next_action` names
`bsc serve`) and `unknown_tool`. Bad arguments are `invalid_request`.

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
| `handoff_disabled` | 403 | Handoff links are off. Use a token. | Do not ask the user to paste the secret. |
| `use_not_configured` | 400 | The item has no use binding. A human binds URLs and a header in the UI, or call `get_secret` if you truly need the value. | Do not reconstruct the request with the raw value. Do not ask the user to paste the secret. |
| `use_not_allowed` | 403 | The URL, method, target address, or value type is outside what this item may be used for. Tell the user what you need. | Do not probe other URLs. Do not ask the user to paste the secret. |
| `upstream_failed` | 502 | The service did not answer. Retry once, then report. | Do not ask for the secret so you can call the service yourself. |
| `unauthorized` | 401 | No or unrecognized credential. Tell the user to check the MCP/client configuration. | Do not guess a token. Do not ask the user to paste a secret or passphrase. |

Human-surface codes, same shape: `bad_passphrase` (401), `forbidden_origin`
(403), `unauthorized` (401), and `internal` (500, generic message, details in
the daemon log only).

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
and the session's scope is recorded and released without an approval prompt —
including `local-approval-only` items, since the session was opened from the
local UI. After an approval, a **grant** for that (token, item) lasts 30
minutes or until the token expires, whichever is first (ADR 0005 §1,
trust-on-first-use); reads under a grant do not prompt. Sessions never renew; the
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
