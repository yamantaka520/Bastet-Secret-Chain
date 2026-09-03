# M6 Validation — rotation, delegation, external approval

**Milestone:** M6 from [`MASTER_PLAN.md`](MASTER_PLAN.md) §6, re-ordered on
2026-09-04 around the pain the first deployment exposed.
**Gate text (as revised):** rotation workflow, pre-authorization, outbound
external approval channel, `use_secret` value-free delegation, audit-head
anchoring, break-glass export.
**Status:** complete in code and tests on 2026-09-04 (123 tests); **partially
activated in production** — see the last section. Nothing here is a release.

## What was built, in the order it was built

| Step | Commit | What |
| --- | --- | --- |
| ① Unattended unseal | `ec86cdf` | `bsc serve --unseal-credential <name>` (systemd `LoadCredentialEncrypted`) / `--unseal-keychain <service>` (macOS). Ledger `unseal_unattended` with source; a failing source exits instead of starting sealed. `deploy/bsc-unattended.conf`. |
| ② `use_secret` | `6207985` | Per-item encrypted binding (https URL patterns, header template with `{value}`, methods). `POST /v1/secrets/{sref}/use` and MCP `use_secret` send one request with the credential injected; the agent never sees it. Same policy as a read plus an SSRF guard. Ledger `secret_used`. `bsc exec` deliberately not built. |
| ③ Telegram channel | `640a713` | Outbound-only: `sendMessage` with ✅/⛔ buttons at ladder step 3, `getUpdates` long-poll for presses; bound to one chat and optional user ids; local-only items get no buttons; decisions ledgered as `external:telegram:<uid>`. |
| ④ Lifecycle | `39365b1` | `POST /v1/vault/passphrase` (one-transaction rewrap, re-encrypt, reindex, new verifier), `DELETE /v1/items/{sref}`, `GET/POST/DELETE /v1/grants…` pre-authorization, `rotation_days` → `rotation_due_at` + 🔄. UI for all four. |
| ⑤ Anchoring & export | `082cc99` | `bsc audit --anchor-file` (truncation / rewrite detection against anchors kept outside the vault); `bsc export` / `bsc import` `BSCX1` bundles under a separate passphrase. |

## Evidence — local, macOS, 2026-09-04

```
cargo fmt --check · clippy -D warnings                          ok
cargo test --workspace                                          123 passed
  new in M6: bsc unattended 3 · bsc-daemon use_secret 6 · telegram 4 ·
             lifecycle_api 2 · bsc-store lifecycle 5 · bsc cli anchors 1 · export/import 1
             (+ parity additions for use_secret)
```

What the tests establish, per step:

- ① The binary really starts: credential → unsealed, ledger record with
  source; wrong credential → non-zero exit and a `denied` record; missing
  `CREDENTIALS_DIRECTORY` → a clear error.
- ② Against a mock upstream on loopback (tests relax the SSRF/https rule via
  `allow_private_upstreams`): the upstream received `Bearer <real value>`
  while the agent's own `Authorization` and `Cookie` headers were dropped; the
  agent's response and the ledger never contain the value; unbound items →
  `use_not_configured`; URL/method outside the binding → `use_not_allowed`;
  strict mode refuses `http://` patterns and private/loopback/metadata
  targets; approval-required items pend before any upstream call; binary
  values cannot be placed in a header.
- ③ Against a mock Bot API: nothing leaves at steps 1–2; step 3 sends one
  message with the approval id in the buttons and no secret material; a
  press from another chat is ignored, from a non-allowed user refused; the
  allowed user's press approves, the agent's poll returns the value, and the
  ledger actor is `external:telegram:777`; a second press is refused; deny
  works; local-only items are announced without buttons and a forged press
  is refused.
- ④ After rotation the old passphrase is dead and the new one opens
  everything — bodies, old versions, names, tags, use bindings, token labels,
  session scopes, and blind-index search — with a fresh salt; deletion removes
  ciphertext, versions, index rows, and grants, closes pending approvals as
  denied, and leaves `item_deleted` in the ledger; a pre-authorized grant lets
  an approval-required read through, is capped at token expiry, and is
  revocable; cadence derives from the last version.
- ⑤ Two anchors, then a tail cut: the chain still verifies (the ADR 0004
  residual) but `--anchor-file` reports `TAIL TRUNCATED … recorded 4 records,
  now has 2`; export refuses the vault passphrase and refuses to overwrite,
  the bundle contains no plaintext, a wrong passphrase or a flipped byte fails
  to open, and a round trip into a fresh vault restores two versions, flags,
  and the use binding under new srefs.

## Production state on `sec.bastet.tw` at the time of writing

- Binary on the host: `0.1.0+f23d51a`, installed 2026-09-04 from the
  `v0.1.0` GitHub Release asset (SHA256SUMS and build-provenance attestation
  verified locally before copying). Earlier that day the host went through
  `91a8875` → `cc846c0` → `240facc` CI artifacts; each upgrade was preceded by
  a `sqlite3` backup-API copy of the vault, all of which remain on the host
  until the operator removes them. `/v1/vault/status`, `bsc --version` and
  `bsc doctor` now all show the build sha, which is what made the day's
  three upgrades hard to tell apart before.
- ① is **active** since 2026-09-04: the operator created
  `/etc/bsc/passphrase.cred` with `systemd-creds encrypt` (the passphrase never
  left their terminal), the drop-in was installed, and two consecutive
  `systemctl restart bsc` came back `sealed:false`,
  `unattended_unseal:"systemd-credential"`, with the ledger's
  `unseal_unattended` record. The host has no TPM2, so the credential is bound
  to `/var/lib/systemd/credential.secret` (root-only) — root on the host can
  unseal, which is the trade-off ADR-level accepted for this step.
- ③ is **active** since 2026-09-04: `deploy/telegram-setup.sh` run by the
  operator on the host (token typed there, validated with `getMe`, encrypted as
  the `telegram-token` systemd credential; chat and user id discovered from one
  message). Journal: `telegram approval channel enabled (outbound only)`. A
  token the operator had pasted into the assistant chat earlier was treated as
  burned and revoked via @BotFather before setup. End-to-end approval through
  the real Bot API: see below.
- Anchoring runs daily since 2026-09-04: `bsc-anchor.timer` →
  `bsc audit --anchor-file /var/lib/bsc-anchors/anchors.jsonl` as root, the
  directory 0700 root so the `bsc` user cannot touch it. First anchor at
  ledger length 45; a second run reported consistent; the `bsc` user is
  refused on the directory.

## Not done — explicitly

- ①, ③, and the binary upgrade are all active in production.
- `use_secret` has run only against a mock upstream, never a real provider.
- The Telegram channel has run only against a mock Bot API.
- `bsc exec` was rejected on purpose: a child process the agent controls can
  print its environment.
- Windows DPAPI / Linux Secret Service unseal; macOS keychain path untested.
- No automatic export scheduling (anchoring is scheduled).
- The `use_secret` SSRF guard resolves the host twice (guard, then client): a
  DNS-rebinding window remains and is recorded in the threat model.
- Approval fatigue defaults (ADR 0005 §6) are still chosen, not measured.

## Incident during activation — no schema migration

The `91a8875` binary opened the production vault (schema 1, created by the
M5-era binary) without complaint and then failed every item-list query with
`no such column: i.use_ct`; the UI showed only "…". Root cause: `schema.rs`
declared version 1 unchanged through M6 while adding columns to `CREATE TABLE
IF NOT EXISTS`, which does nothing to an existing table. Fix: schema version 2
with `schema::migrate` run by `Vault::open` (columns added, `approval` and
`access_grant` rebuilt, `pragma_foreign_key_check` must be empty, ledger
`schema_migrated`, one transaction), tested against a file rewritten into the
exact schema-1 shape (`crates/bsc-store/tests/migrate.rs`). The M6 tests all
passed because every test creates a fresh vault — a gap the new test closes.

Production recovery, 2026-09-04: a consistent copy of the schema-1 file was
taken first (`sqlite3` backup API, `/var/lib/bsc/vault.pre-schema2-20260904.bsc`),
then the `cc846c0` artifact was installed and the service restarted. The
migration ran at open: `schema_version` 2, both new columns present, no item
foreign key on `approval`, cascade on `access_grant`, `pragma foreign_key_check`
empty, ledger record 25 `schema_migrated` followed by the unattended unseal,
`bsc audit` intact at 27 records, zero errors in the new invocation, UI
rendering again. The pre-migration copy stays on the host until the operator
decides to remove it.

## End-to-end through the real Telegram Bot API — 2026-09-04

Operator-created probe: item `test/telegram-probe` (api_key, approval
required), token `telegram-probe` scoped to `test`, value saved on the host
only. Agent side run over `ssh ssh.bastet.tw` with curl against loopback.

| UTC | Event | Evidence |
| --- | --- | --- |
| 20:58:33 | `GET /v1/secrets/{sref}` → **202** `approval_pending`, `apr_aba0c373addfa1a7`, poll hint 5 s, 5-min expiry | response body; ledger 33 `approval_requested` |
| 20:58:33 / 20:58:54 | ladder steps 1 and 2 (local notifier only) | ledger 34, 35 `approval_escalated` |
| 20:59:35 | step 3: one Telegram message with ✅/⛔ to chat 8686567559 | ledger 36 `approval_escalated`, 37 `approval_notified` `{channel: telegram, buttons: true}` |
| 20:59:52 | operator pressed ✅ on the phone | ledger 38 `approval_decided` **approved** by `external:telegram:8686567559`, grant issued |
| 20:59:52 | poll returned `approved` with the value (19 bytes, correct) | ledger 39 `secret_read` |
| after | second read under the TOFU grant → 200 with no new approval | see below |

The ladder timings match ADR 0005 (0 / 20 / 60 s). Nothing about the secret
appeared in the Telegram message, the journal, or the ledger. Two mistakes on
the way, both the assistant's: the first poll loop matched `approval_pending`
instead of the response's `status: "pending"` and exited early (harmless); and
the operator was told to scope the token as `test/*`, which the matcher took
literally — fixed by normalizing `test/*` and `test/` to `test`.
