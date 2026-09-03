# M3 Validation — Web UI

**Milestone:** M3 from [`MASTER_PLAN.md`](MASTER_PLAN.md) §6.
**Gate text:** Upload → encrypt → classify → copy reference, approval inbox,
task-session control, ⏰ expiry panel, local OS notifications, per-item audit
view; e2e test on all item types.
**Status:** gate met with one stated substitution (below), 2026-09-03 — local
evidence plus three-platform CI on commit `5453193`. Nothing here is a release.

## What was built

| Piece | Purpose |
| --- | --- |
| `ui/` (Vite 7 · React 19 · TypeScript 5.9, no UI library) | The operator's single-page app: login, overview, secrets with path tree and filters, item drawer with detail / versions / per-item audit, new-item modal with emoji type grid and file drop, tokens with a shown-once mint sheet, approval inbox, task-session control in the header, expiry panel, audit chain browser; zh-Hant default and English; light and dark; `/`, `Esc`, `a`/`d`, `c` keys |
| `bsc-daemon::ui` | Serves the embedded `ui/dist` from `/` with CSP, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, immutable caching for hashed assets; unknown `/v1` paths still answer in the error contract |
| `bsc-daemon/build.rs` | Guarantees `ui/dist/index.html` exists so `cargo build` never fails on a checkout without Node; the placeholder says how to build the UI |
| `bsc-daemon::notify::OsNotifier` | Desktop notification for each escalation step via `osascript` / `notify-send` / PowerShell, best effort, never carrying secret material; default for `bsc serve` |
| `GET /v1/audit?subject=` | Per-item ledger view for the drawer |
| `bsc init --passphrase-stdin` | Scriptable vault creation, which also closed the M2 gap "init untested end to end" |

### How the UX plan shows up

- **Emoji is the type marker** (🔐 🔑 ☁️ 🔥 🎫 🖥️ 📜 🗂️) in the list, the type
  picker, the drawer, the inbox, and the expiry panel — never decoration.
- **📋 Copy reference** copies `http://127.0.0.1:8787/v1/secrets/sref_…` and
  the toast says, in so many words, that the URL alone grants nothing and
  links to minting a token scoped to that item's path (ADR 0002).
- **Reveal** is a smaller, deliberate action; for approval-required items it
  demands the passphrase again; the value auto-hides after 30 s.
- **Approval inbox** shows the agent's reason verbatim in large type, the
  auto-deny countdown, the escalation count, and single-key approve/deny.
  The nav badge and the document title carry the pending count; the browser
  `Notification` API is offered as an opt-in complement to the OS notifier.
- **Task session control** lives in the header with a live countdown and an
  End button; it never renews.
- **Expiry panel** lists secrets and tokens by time left with ⏰/⛔ badges;
  the list rows carry the same badges.
- **Per-item audit** is a tab in the drawer.
- Values are never written to `localStorage`; only theme and locale are.

## Evidence — local, macOS, 2026-09-03

```
npm --prefix ui run typecheck                                 ok
npm --prefix ui run build                                     243 KB JS · 8.7 KB CSS (gzip 76 KB · 2.4 KB)
cargo fmt --all -- --check                                    ok
cargo clippy --workspace --all-targets -- -D warnings          ok (0 warnings)
cargo test --workspace                                         82 passed, 0 failed
  new in M3: bsc-daemon ui_and_types 2 · bsc cli init_from_stdin 1
```

### Automated

**`ui_and_types::every_item_type_round_trips_through_the_human_surface`** —
for each of the eight types, exactly the calls the UI makes: create (with a
binary `value_base64` for 🗂️ file) → listed with decrypted name/path/tags →
the copy button's URL returns `401 unauthorized` when pasted alone → reveal,
demanding the passphrase where the type defaults to approval-required and
returning `Cache-Control: no-store` → the per-item ledger shows
`item_created` and a human `secret_read` with reason `revealed in UI`, and
never the value.

**`ui_and_types::embedded_ui_is_served_with_hardening_headers_and_v1_stays_json`**
— `/` is HTML with CSP / DENY / no-referrer / nosniff; deep client routes get
the document; `/v1/does-not-exist` is contract JSON; hashed assets are
immutable-cached.

**`cli::init_from_stdin_…`** — creates `0700` dir and `0600` vault, prints the
Argon2id parameters, verifies with `audit`, refuses to overwrite.

### Manual, in a real browser against `bsc serve` on 127.0.0.1:8797

Performed with the in-app browser and recorded here because there is no
browser-driven e2e suite yet (see below):

1. Login page renders (dark, system theme); wrong-passphrase path shows
   `bad_passphrase`; clicking **解封** unseals and lands on the overview with
   six tiles, chain **✅ 完整**, KDF parameters, and the head hash.
2. **New secret** modal: emoji type grid, path/name/tags/env, textarea with
   drop zone, approval default follows type (🔥 pre-checked), created →
   drawer opens, tree shows `prod › gcp`, toast confirms.
3. **📋 複製參照** toast: “這個 URL 本身不授予任何權限。Agent 還需要一把受限
   token。”
4. **👁 顯示** on an approval-required item asks for the passphrase; value
   shown with a 30 s countdown; the drawer's 稽核紀錄 tab lists the reveal.
5. Six more items of the other types created through the API appear in the
   list on the periodic refresh with correct emoji, badges (🔴 需人工核准,
   ⏰ 即將到期), path tree counts, and tag chips.
6. An agent token minted; the agent read an api_key directly, then asked for
   the service account: `202 approval_pending`. The nav badge and title show
   **(1)**; the inbox shows `deploy-bot 想讀取 🔥 firebase-admin`, the reason
   verbatim, the countdown, and **已升級 2 階** after the 20 s step; the daemon
   log shows the `OsNotifier` firing at steps 1 and 2. **✅ 核准** clears the
   inbox; the agent's poll returned the value once, then `consumed`, then a
   direct read passed on the grant.
7. Tokens, Expiry (⏰ 4 天 / 19 天 / 23 小時), and Audit chain (21 records,
   intact, escalations and `approved` visible) pages render; light theme and
   English render correctly.
8. Task session `prod/aws, prod/gcp` opened from the header; the pill shows
   the countdown. An agent read of the approval-required `billing-account`
   (`prod/aws`) then returned `200` with no prompt, while the approval-required
   `tls-cert-2026` (`prod/web`, outside the window) still returned
   `202 approval_pending`.

Two defects found in that pass were fixed before this commit: the inbox
countdown read “4m 32s 秒後” (string bug), and the list did not refresh when
items were created outside the tab (now polls every 10 s and on focus).

## The substitution, stated plainly

The gate asks for an **e2e test on all item types**. What exists is an
API-level round trip of every type through the exact calls the UI makes, plus
a manual browser pass recorded above. There is **no browser-driven automated
e2e suite** (Playwright or similar): it would need a browser download in CI
and was judged not worth the flakiness at this stage. This is the one place
M3 is met by substitution rather than to the letter; it is listed in the
master plan's open questions so it is not forgotten.

## Not done — explicitly

- **No browser-driven e2e.** See above.
- **Enter in the passphrase field did not submit under the automation tool;
  clicking the button did.** Native form submission should handle Enter in a
  real browser; this is recorded as unverified rather than fixed blind.
- **OS notifications have no Approve/Deny actions** and are best-effort
  shell-outs; on a headless or minimal host they silently do nothing beyond
  the log line. A native integration belongs with the tray in M4.
- **No command palette (⌘K).** `/`, `Esc`, `a`/`d`, `c`, `Enter` exist.
- **No item deletion or rename in the UI** — the API has none yet.
- **No passphrase rotation, keychain unseal, auto-reseal timer** — unchanged.
- **Human sessions idle out at 15 minutes** and the UI simply returns to
  login; there is no warning before it happens.
- Bundle is a single 243 KB chunk; fine on loopback, not tuned.
- Vite 7 / React 19 / TypeScript 5.9 were chosen over the newest majors on the
  registry for the same reason as the Rust dependencies: known APIs.

## CI evidence

| Run | Commit | Ubuntu | macOS | Windows | Hygiene |
| --- | --- | --- | --- | --- | --- |
| [`33769473982`](https://github.com/yamantaka520/Bastet-Secret-Chain/actions/runs/33769473982) | `5453193` | ✅ | ✅ | ✅ | ✅ |

Each Rust job first ran `npm ci`, `npm run typecheck`, and `npm run build` for
the UI, then `cargo fmt --check`, `cargo clippy --all-targets --locked
-D warnings`, `cargo test --workspace --locked` (82 tests) with the real
`ui/dist` embedded, and the known-answer regeneration check.
