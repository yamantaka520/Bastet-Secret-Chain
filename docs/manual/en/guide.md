# User guide

**Applies to:** Bastet Secret Chain 0.2.0
**Languages:** [繁體中文](../zh-Hant/guide.md) · [简体中文](../zh-Hans/guide.md) · **English** · [日本語](../ja/guide.md) · [한국어](../ko/guide.md)
**See also:** [Installation](install.md) · [Agent guide](agents.md)

This guide is for the person who owns the vault: putting credentials in,
deciding which agent may read what, answering approval prompts, and proving
afterwards who read what.

---

## 1. The ideas, in one table

| Term | What it means |
| --- | --- |
| **Vault** | One encrypted file. *Sealed* means the key is not in memory and nothing can be read — including by you. *Unsealed* means a human typed the passphrase. |
| **Item** | One credential: a login, an API key, a service-account JSON, an SSH key. Has a path, a name, a type, tags. |
| **Version** | Every change adds a version; old ones stay readable. Rotating is adding a version, not overwriting. |
| **Reference (`sref_…`)** | The item's stable address, e.g. `https://…/v1/secrets/sref_7Qn4…`. **It grants nothing on its own.** Safe to paste into a ticket or a config file. |
| **Token (`bsct_…`)** | What an agent authenticates with. Scoped, expiring, revocable, rate-limited. Shown exactly once, at mint. This *is* a credential. |
| **Scope** | Path prefixes and tags a token may reach. `prod` covers everything under `prod/`. Nothing else is even listed. |
| **Approval** | A high-value item asks a human before each read. The agent waits; it does not fail. |
| **Grant** | After you approve once, that token may read that item without prompting until the grant expires. You can also grant in advance. |
| **Task session** | A window you open before handing work to an agent. Reads inside the window and scope are recorded without interrupting you. It never extends itself. |
| **Audit chain** | An append-only ledger where each record contains the hash of the previous one. Any edit breaks the chain and is visible. |

Two rules follow from this and are worth learning once:

- **A reference URL is not a secret. A token is.** URLs end up in shell
  history, logs and agent transcripts; that is fine, because a URL alone
  releases nothing.
- **Nobody can recover your passphrase.** Not the maintainers, not an
  administrator, not an AI assistant. Back up the vault file.

---

## 2. First five minutes

1. Open <http://127.0.0.1:8787/> (or your server's address) and **unseal** with
   your passphrase. The passphrase goes to the daemon on that machine and
   nowhere else.
2. Press **New secret**. Fill in a path such as `prod/gcp`, a name such as
   `firebase-admin`, pick the type, then paste the value — or drop the
   credential file straight onto the field. It is encrypted before it reaches
   disk.
3. Press **📋 Copy reference**. You now have a URL you can paste anywhere. It
   releases nothing by itself.
4. Go to **Agent tokens → Mint token**. Give it a label naming the agent, a
   path scope no wider than that agent's job, and a lifetime no longer than the
   work. The `bsct_…` value appears **once** — put it straight into the agent's
   configuration file.
5. Hand the agent the reference and let it read. Watch the read appear in
   **Audit chain**.

---

## 3. The interface

Seven tabs, left to right.

### 🏠 Overview

Item count, what expires within 30 days, pending approvals, active task
sessions, live tokens, and the state of the audit chain. The version line shows
the build, e.g. `0.2.0+f23d51a` — useful when a machine behaves unexpectedly
after an upgrade. Also here: **Change passphrase**.

### 🗂️ Secrets

The list, with a path tree and filters by type and environment. Search covers
names, paths and tags; it works through a blind index, so the search terms are
never stored in the clear. Press `/` to jump to it.

Badges tell you what is special about an item:

| Badge | Meaning |
| --- | --- |
| 🔴 | Every read needs your approval |
| 🏠 | Approvable only in this UI — no external channel |
| 🔗 | Has a *use binding*: an agent can use it without seeing it |
| 🔄 | Rotation overdue |

Opening an item gives four tabs: **Detail** (metadata, expiry, rotation
cadence, delete), **Versions** (history, add a new version), **Use binding**
(section 7), and **Audit** (every event about this item).

**Reveal** shows the value for a few seconds, then hides it. For an
approval-required item you must type the passphrase again. Copying puts it on
the clipboard — clear the clipboard afterwards.

### 🎫 Agent tokens

Mint, inspect and revoke. Each token has a label, a scope, a lifetime, an
optional read quota and a per-minute rate limit. The list shows what is live,
expired or revoked, and how much quota is left. **Revoke** takes effect
immediately.

The **Pre-authorizations** panel on this tab is described in section 5.

### 🔔 Approvals

The inbox. Each entry shows which token wants which item, the reason the agent
gave, how many reminder steps have passed, and the countdown to automatic
denial. `a` approves, `d` denies. Approving also issues a grant so the same
token does not ask again for that item until the grant expires.

### ▶️ Task sessions

Open a window before you hand work to an agent: a scope and a duration (15
minutes to 2 hours; the hard ceiling is 8 hours). Reads inside it are recorded
without prompting. The window never extends itself; when it ends, prompting
returns.

### ⏰ Expiry

Items and tokens sorted by how soon they expire. Use it to rotate before
something breaks rather than after.

### ⛓️ Audit chain

Every event: unseal, create, read, mint, revoke, approve, delete, migrate.
**Re-verify** recomputes the whole chain and reports intact or the record where
it broke. The chain contains item ids, actors and reasons — never values.

---

## 4. Everyday tasks

**Add a credential.** New secret → path, name, type, tags, value. Optional:
an expiry date, a rotation cadence in days, and *Ask me before every read*.

**Rotate.** Open the item → Versions → Add version. The old version stays
readable, agents get the new one, and the rotation clock resets. Set a cadence
in days on the Detail tab and the 🔄 badge appears when it is overdue.

**Choose what needs approval.** Service accounts, cloud root keys and signing
certificates require approval by default; logins and ordinary API keys do not.
Change it per item. If it prompts too often, that is a signal to use a task
session or a pre-authorization — not to switch approval off.

**Delete.** Detail → Delete item, with a reason. Ciphertext, versions, index
rows and grants go. The ledger keeps the history: `item_deleted`, who and why.
There is no undo.

**Change the passphrase.** Overview → Change passphrase. Every data key is
rewrapped and the index rebuilt in a single transaction; the old passphrase
stops working and everyone is logged out. The item values themselves are not
re-encrypted, so it is fast even for a large vault.

**Lock it.** **Lock** seals the vault immediately: the key leaves memory,
agents get `vault_sealed`, and the next read waits for a human. Do this when
you leave a shared machine.

---

## 5. Giving an agent access

Four dials. Turn them down before you turn them up.

| Dial | Set it to |
| --- | --- |
| **Scope** | The narrowest path prefix that covers the job. `prod/mobile`, not `prod`. |
| **Lifetime** | No longer than the work. A day for an assistant, an hour for a pipeline. |
| **Read quota** | For a pipeline that reads three secrets, set 3. |
| **Rate limit** | The default 60 per minute is generous; lower it for a machine. |

One token per agent per project. That way a revocation costs one agent one
project, and the ledger says which agent did what.

**Renewal.** A token can extend itself only inside the last quarter of its
lifetime (plus a five-minute grace period), and never past its hard maximum.
Renewal never widens scope.

**Pre-authorization.** If you know an agent will need an approval-required item
during a run, grant it in advance: Agent tokens → Pre-authorize → token, item,
duration. It is capped at the token's expiry and you can revoke it at any time.
This is how you avoid being asked at an inconvenient moment without weakening
the item for everyone.

---

## 6. Approvals, and not being worn down by them

When an approval-required item is read, the agent gets "pending" and waits.
You get a reminder ladder:

| Step | When | What happens |
| --- | --- | --- |
| 1 | immediately | Desktop notification |
| 2 | after 20 s | Repeated, with sound |
| 3 | after 60 s | External channel, if configured (Telegram) |
| — | after 5 min | **Automatically denied** and recorded |

Every step is written to the ledger, so a decision made under time pressure is
still visible afterwards.

The external channel is outbound only. The message names the item and the
reason; it never contains the value or a link that would release it. An item
marked **local approval only** is announced there but can only be approved in
the UI.

Approval fatigue is a security problem, not an annoyance: a person clicking
Approve reflexively is worse than no approval at all. If you are being asked
too often, open a **task session** for the duration of the work, or
**pre-authorize** the specific item and token. Both are bounded and both are
recorded. Turning approval off entirely is the option to reach for last.

---

## 7. Letting an agent use a secret without seeing it

For an item that is only ever sent to one service — a deploy key, a webhook
token — you can bind it to that service instead of handing over the value.

Open the item → **Use binding** → allowed URL patterns (`https://` only,
trailing `*` for a prefix), a header template such as
`Authorization: Bearer {value}`, and the allowed methods.

The agent then calls `use_secret` with a URL and a body. The daemon substitutes
the credential, sends the request itself, and returns the service's answer. The
value never enters the agent, the transcript, or a log. Requests outside the
binding are refused, and so are non-HTTPS URLs and internal addresses.

Clear the binding to switch back to ordinary reads.

---

## 8. Proving what happened, and getting your data out

**Verify the chain.** Audit chain → Re-verify, or offline while the vault is
sealed:

```sh
bsc audit --vault ~/.bsc/vault.bsc
```

**Anchors.** Verification proves nothing was *edited*, but the owner of the
file could in principle drop records from the end. Anchoring records the chain
length and head outside the vault:

```sh
bsc audit --anchor-file ~/anchors/bsc.jsonl
```

Keep that file where the vault's owner cannot silently rewrite it: another
disk, a log shipper, a git repository. On a server, run it daily with the timer
from the [installation manual](install.md#46-daily-ledger-anchor-recommended).

**Break-glass export.** A full export of every item and every version, sealed
under a *different* passphrase:

```sh
bsc export --out ~/bsc-export-2026-09-04.bscx
bsc import --in ~/bsc-export-2026-09-04.bscx     # into another vault
```

It refuses to reuse the vault passphrase and refuses to overwrite a file. The
bundle contains no plaintext. Tokens, sessions, approvals and the ledger are
deliberately not exported: an import is a fresh start with the same
credentials, not a clone of an authorization state.

Treat the export like the vault itself: encrypted, off-machine, and never in a
repository.

---

## 9. Keyboard

| Key | Action |
| --- | --- |
| `/` | Search |
| `Esc` | Close the drawer or dialog |
| `a` / `d` | Approve / deny in the inbox |

---

## 10. Habits worth keeping

1. Type the passphrase yourself. Nobody else — human or AI — needs it, ever.
2. Never paste a `bsct_…` token into a chat. It goes in a configuration file.
3. Mint narrow, short tokens and revoke them when the work is done.
4. Back up the vault file, keep a copy off the machine, and test that
   `bsc audit` reads the backup.
5. Read the ledger occasionally when nothing is wrong. That is how you learn
   what normal looks like.
