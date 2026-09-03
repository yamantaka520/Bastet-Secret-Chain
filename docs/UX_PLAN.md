# Web UI / UX Plan

**Status:** implemented in M3 (2026-09-03) as `ui/`; see `M3_VALIDATION.md` for what shipped and what did not (no ⌘K palette yet).
Goal: a vault a human *enjoys* using, so that secrets actually get stored here
instead of in a notes app — without the pleasantness costing safety.

## 1. Principles

1. **Recognizable at a glance.** Emoji-led types and colored path chips, so the
   list is scannable without reading every label.
2. **Safe defaults are the easy path.** The big obvious button copies a
   *reference*; revealing a plaintext value is a smaller, deliberate action.
3. **Say what just happened.** Every copy, reveal, and mint shows what authority
   was actually granted, in plain language.
4. **No plaintext detours.** File uploads encrypt in the browser-to-daemon flow
   without a plaintext temp file; nothing sensitive lands in `localStorage`.
5. **Keyboard first.** `⌘K` command palette, `/` to search, `c` to copy
   reference, `⏎` to open.

## 2. Information architecture

```
┌ Sidebar ─────────────┬ Main ───────────────────────────────────┐
│ 🔍 Search            │ Filter bar: type · env · tag · expiry    │
│                      ├──────────────────────────────────────────┤
│ 📂 prod              │ 🔑  stripe-live-key      prod/payments 🔴 │
│   └ payments         │ ☁️  aws-billing          prod/aws     ⏰  │
│   └ aws              │ 🔥  firebase-admin.json  prod/mobile  🔒  │
│ 📂 staging           │ 🖥️  deploy-ssh-key       prod/infra      │
│ 📂 personal          │                                          │
│                      │                                          │
│ ⏰ Expiring (3)      │                                          │
│ 🔄 Rotate soon (1)   │                                          │
│ 🚨 Denied reads (0)  │                                          │
│ 🎫 Agent tokens      │                                          │
│ 🧾 Audit chain       │                                          │
└──────────────────────┴──────────────────────────────────────────┘
```

Hierarchy is the path tree in the sidebar; tags, environment, and expiry are
orthogonal filters, so one item is filed once but findable many ways.

## 3. Type system (emoji is the type marker, not decoration)

| Emoji | Type | Upload affordance |
| --- | --- | --- |
| 🔐 | Login | form: account, password, TOTP seed, URL |
| 🔑 | API key | form: key, optional secret, provider |
| ☁️ | Cloud key | form: access key id, secret, region, account |
| 🔥 | Service account | drag-and-drop JSON, parsed for project id and expiry |
| 🎫 | OAuth | drag-and-drop `client_secret*.json`, or form |
| 🖥️ | SSH key | drag-and-drop key pair, passphrase field |
| 📜 | Certificate | drag-and-drop PEM/p12, chain preview, expiry read out |
| 🗂️ | File | any blob, with a declared content type |

Status badges: 🔴 approval-required · ⏰ expiring · 🔄 rotation overdue ·
🔒 sealed-only preview · ✅ healthy.

## 4. The copy interaction (the core of the product)

Each item row has **📋 Copy reference**. Pressing it copies:

```
http://127.0.0.1:8787/v1/secrets/sref_7Qn4…
```

and shows a toast that states the truth without a lecture:

> 📋 Reference copied — this URL alone grants nothing.
> An agent also needs a scoped token. [Mint a token for this item →]

The token minting sheet asks for: label, scope (this item / this path / these
tags), expiry, max reads, and whether reads require approval. It shows the token
value **once**, with a warning that it will not be shown again.

A separate, off-by-default **⚡ Handoff link** action exists for the
copy-and-paste-into-a-chat case. It mints a single-use, 60-second, loopback-bound
link, labels it clearly as a live credential, and shows a visible countdown.

## 5. Approvals, sessions, and expiry

These three surfaces are where the human meets the automated loop, so they get
the most design attention.

**▶️ Task session control** sits in the header. Starting one asks for a scope
and a duration (30 minutes default), then shows a live countdown and the count
of reads it has covered. Ending it early is one click. It never renews itself;
when it lapses the header returns to its resting state rather than quietly
extending.

**✋ Approval inbox** shows, per pending request: the item, the requesting
token's label, the reason the agent gave, and a countdown to auto-deny. Approve
and deny are single keystrokes. The reason is displayed prominently and
verbatim — it is often where a manipulated agent gives itself away, and a
truncated or prettified reason defeats that.

Notifications escalate at 0 s (OS notification with Approve/Deny actions, tray
badge, title badge), 20 s (repeat, with sound), and 60 s (external channel, if
configured). An external message never contains secret material and never
contains a link that alone releases one.

**⏰ Expiry panel** lists tokens and credentials by time remaining, with a
Renew action that extends a token rather than issuing a new value, so nothing
in the agent's configuration has to change.

## 6. Health and history

- **Dashboard tiles:** total items, expiring in 30 days, rotation overdue,
  active tokens, reads in the last 24 h, denied reads.
- **Per-item audit tab:** who read it, with which token, when, and the outcome —
  rendered as a chain with a ✅/⚠️ verification state at the top.
- **Approval inbox:** pending agent requests with item, token label, and a
  requested reason; approve or deny in one keystroke.

## 7. Look and feel

Light and dark, following the system theme with a manual override. A calm
neutral ground with one accent color; emoji and status badges carry the color
load so the interface does not become noisy. Type scale and spacing follow the
Bastet Workstation shell so the two products feel related. Locale-ready with
zh-Hant as the default and English second; no string is hard-coded in a
component.

## 8. Accessibility

Never color alone: every status badge pairs an emoji with text. Contrast at
WCAG AA in both themes. Full keyboard operation, visible focus rings, and
`aria-live` announcements for copy, reveal, approve, and revoke.
