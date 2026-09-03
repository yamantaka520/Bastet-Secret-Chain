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

- Binary on the host: upgraded on 2026-09-04 to the CI artifact of `91a8875`
  (sha256 verified against the artifact's `.sha256`; previous binary kept as
  `/usr/local/bin/bsc.prev`). It now carries ①–⑤. The restart left the vault
  sealed, as expected without ①'s credential.
- ① is **staged, not active**: `/etc/bsc/unattended.conf.staged` and
  `/etc/bsc/` exist; `/etc/bsc/passphrase.cred` does not — it must be created
  by the operator typing the passphrase into `systemd-creds encrypt`. Until
  then every restart still needs a human unseal.
- ③ is not configured on the host (no bot token / chat id supplied).
- No anchor timer runs on the host yet; `bsc audit --anchor-file` is a manual
  command. A systemd timer writing to a location outside `/var/lib/bsc` is
  the obvious next step.

## Not done — explicitly

- **Production activation of ①, ③, and the host binary upgrade** (above).
- `use_secret` has run only against a mock upstream, never a real provider.
- The Telegram channel has run only against a mock Bot API.
- `bsc exec` was rejected on purpose: a child process the agent controls can
  print its environment.
- Windows DPAPI / Linux Secret Service unseal; macOS keychain path untested.
- No anchor scheduling; no automatic export scheduling.
- The `use_secret` SSRF guard resolves the host twice (guard, then client): a
  DNS-rebinding window remains and is recorded in the threat model.
- Approval fatigue defaults (ADR 0005 §6) are still chosen, not measured.
