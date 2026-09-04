# Installation manual

**Applies to:** Bastet Secret Chain 0.2.0 · macOS, Windows, Linux
**Languages:** [繁體中文](../zh-Hant/install.md) · [简体中文](../zh-Hans/install.md) · **English** · [日本語](../ja/install.md) · [한국어](../ko/install.md)
**See also:** [User guide](guide.md) · [Agent guide](agents.md)

Everything is one file. `bsc` is a single binary that is the command line, the
daemon, the web server and the embedded Web UI at once. There is no runtime to
install, no database server, no container required. The vault is one SQLite
file that only you can decrypt.

---

## 1. Before you start

| You need | Why |
| --- | --- |
| A passphrase you can remember and have never used elsewhere | It derives the key that encrypts everything. Nobody can reset it — not the maintainers, not an administrator, not an AI assistant. |
| 60 MB of disk | Binary plus vault. |
| A terminal | Installation and the first vault creation are command-line steps. Everything after that is the Web UI. |

**Never let anyone else generate or see the passphrase, including an AI
assistant helping you install this.** Type it yourself, into your own terminal
or the Web UI. If a chat window has ever contained it, treat it as burned and
change it.

---

## 2. Choose your setup

- **Personal machine** — the vault runs on your laptop, reachable only at
  `127.0.0.1`. Agents on the same machine use it. Go to section 3.
- **Shared server** — the vault runs on a Linux host behind a TLS reverse
  proxy so several people and remote agents can reach it. Go to section 4.
  Do section 3 first on the server itself; section 4 replaces the auto-start
  and exposure parts.

---

## 3. Personal machine

### 3.1 Install the binary

**Option A — the install script (recommended).** Read the script before
running it; it is not meant to be piped from the network into a shell.

```sh
# macOS and Linux
curl -fsSLO https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.sh
less install.sh          # read it
sh install.sh v0.2.0
```

```powershell
# Windows
Invoke-WebRequest -Uri https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.ps1 -OutFile install.ps1
notepad install.ps1      # read it
.\install.ps1 -Version v0.2.0
```

The script downloads the archive for your platform, checks it against the
`SHA256SUMS` published with the same release, and installs `bsc` into
`~/.local/bin` (macOS, Linux) or `%LOCALAPPDATA%\Programs\bsc` (Windows). Add
that directory to your `PATH` if the script says so.

That check proves the archive was not corrupted or swapped in transit. It does
not prove who built it, because the sums come from the same release page. For
that, verify the build provenance attestation as well:

```sh
gh attestation verify bsc-0.2.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo yamantaka520/Bastet-Secret-Chain
```

From v0.2.0 the checksum file is signed as well, with Sigstore keyless
signing:

```sh
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/yamantaka520/Bastet-Secret-Chain/.github/workflows/release.yml@refs/tags/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

That proves the file came out of this repository's release workflow at a tag.
It does not prove a maintainer approved that tag — there is no project signing
key, and anyone who can push a tag here can produce a valid signature.
[`SECURITY.md`](../../../SECURITY.md) states this plainly.

**Option B — build from source.** Requires Rust (stable) and Node.js 22.

```sh
git clone https://github.com/yamantaka520/Bastet-Secret-Chain
cd Bastet-Secret-Chain
npm --prefix ui ci && npm --prefix ui run build   # builds the Web UI
cargo install --path crates/bsc --locked          # embeds it and installs bsc
```

Check what you got. The version carries the git commit it was built from, so
you can always tell which build a machine is running:

```sh
bsc --version        # bsc 0.2.0+9f3c1ab
```

### 3.2 Create the vault

```sh
bsc init
```

You are prompted for the passphrase twice. This creates `~/.bsc/vault.bsc`
with `0600` permissions (set `BSC_HOME` to put it elsewhere, or pass
`--vault /path/to/vault.bsc`).

Choose a long passphrase. Four or five unrelated words beat a short mangled
word. The key derivation is Argon2id with parameters recorded in the file, so
a slow guess stays slow, but nothing saves a passphrase that appears in a
password list.

**Back up the vault file now and after every batch of changes.** Copying the
file is enough; it is encrypted at rest. Losing it and the passphrase means
losing the contents, permanently.

### 3.3 Start it, and keep it started

```sh
bsc service install     # start now and at every login
bsc doctor              # ✅/⚠️/❌ checklist
```

`bsc service install` writes a launchd agent on macOS, a `systemd --user` unit
on Linux, or a Task Scheduler logon task on Windows, then starts the daemon.
Add `--dry-run` to print the definition and the commands without touching
anything.

To run it in the foreground instead:

```sh
bsc serve               # Ctrl-C to stop
```

The daemon listens on `127.0.0.1:8787` and **starts sealed**: it holds no key
until a human unseals it. Open <http://127.0.0.1:8787/>, enter the passphrase,
and continue in the [user guide](guide.md).

`bsc doctor` checks file permissions, the ledger, whether the daemon answers,
whether the UI is embedded, whether auto-start is installed, and the clock. Run
it whenever something feels wrong; every line is either ✅, ⚠️ with a reason,
or ❌ with the fix.

### 3.4 Unattended unseal on macOS (optional)

By default a human unseals after every restart. That is the safe default. On a
workstation you can let the daemon unseal itself from the login keychain:

```sh
security add-generic-password -s bsc-vault -a bsc -w   # prompts for the passphrase
bsc service install --dry-run                          # see the definition
```

Then add `--unseal-keychain bsc-vault` to the service's arguments. Anyone who
can unlock your login keychain can then unseal the vault. On a laptop that
travels, prefer typing the passphrase.

### 3.5 Uninstall

```sh
bsc service uninstall   # stops the daemon, removes the definition
rm ~/.local/bin/bsc     # or wherever it was installed
```

The vault file is left alone. Delete `~/.bsc/vault.bsc` yourself if you mean to
destroy the contents; there is no undo.

---

## 4. Shared server (Linux, systemd, nginx)

The daemon never terminates TLS and never listens on a public interface. It
stays on loopback and a reverse proxy in front of it does TLS. The reference
configurations in [`deploy/`](../../../deploy) are the ones running in
production; read [`docs/DEPLOY_REVERSE_PROXY.md`](../../DEPLOY_REVERSE_PROXY.md)
for what that arrangement does and does not protect.

### 4.1 Service account and vault

```sh
sudo useradd --system --home /var/lib/bsc --shell /usr/sbin/nologin bsc
sudo install -d -m 0700 -o bsc -g bsc /var/lib/bsc
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo -u bsc bsc init --vault /var/lib/bsc/vault.bsc    # type the passphrase yourself
```

### 4.2 systemd unit

Install [`deploy/bsc.service`](../../../deploy/bsc.service), which runs as the
`bsc` user with `ProtectSystem=strict` and only `/var/lib/bsc` writable:

```sh
sudo install -m 0644 deploy/bsc.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bsc
systemctl status bsc
```

Adjust `--bind` and `--public-origin` in the unit to your port and hostname.
`--public-origin https://secrets.example.com` tells the daemon that a TLS proxy
fronts it: it accepts that Origin, marks the session cookie `Secure`, throttles
logins per forwarded client address, and writes `exposure_acknowledged` into
the ledger. Without it, remote browsers are refused.

### 4.3 nginx and TLS

Start from [`deploy/nginx-bsc.conf`](../../../deploy/nginx-bsc.conf).
The parts that matter:

- a real certificate, HTTP redirected to HTTPS;
- `proxy_pass http://127.0.0.1:8787;` with `X-Forwarded-For` set from the real
  client address (behind Cloudflare, from `CF-Connecting-IP`);
- `limit_req` on `/v1/vault/unseal` and `/v1/items` so a stolen session cannot
  be brute-forced through the proxy.

Then check from your own machine:

```sh
bsc doctor --url https://secrets.example.com
```

### 4.4 Unseal without a human (optional, recommended for servers)

Otherwise every reboot leaves the vault sealed until someone types the
passphrase. systemd can hold it as an encrypted credential that only root can
decrypt on that host:

```sh
read -rsp "Vault passphrase: " PW && echo && \
  printf '%s' "$PW" | sudo systemd-creds encrypt --name=bsc-passphrase - /etc/bsc/passphrase.cred && \
  unset PW && sudo chmod 0600 /etc/bsc/passphrase.cred
```

Then install [`deploy/bsc-unattended.conf`](../../../deploy/bsc-unattended.conf)
as a drop-in, which adds `LoadCredentialEncrypted=` and
`--unseal-credential bsc-passphrase`:

```sh
sudo install -d /etc/systemd/system/bsc.service.d
sudo install -m 0644 deploy/bsc-unattended.conf /etc/systemd/system/bsc.service.d/unattended.conf
sudo systemctl daemon-reload && sudo systemctl restart bsc
curl -s http://127.0.0.1:8787/v1/vault/status
```

Expect `"sealed":false,"unattended_unseal":"systemd-credential"`. Understand the
trade: **root on that host can now unseal the vault.** Without a TPM the
credential is bound to `/var/lib/systemd/credential.secret`, which root reads.
If a configured unseal source fails, the daemon exits rather than starting
sealed and pretending to be healthy.

### 4.5 Telegram approval channel (optional)

When an agent asks for a high-value secret and nobody is at the machine, the
daemon can send one message with Approve / Deny buttons. It is outbound only —
no inbound port, no webhook — and the message never contains the secret or a
link that would release it.

Run [`deploy/telegram-setup.sh`](../../../deploy/telegram-setup.sh) **on the
server**; the bot token is typed there and never leaves it:

```sh
sudo ./telegram-setup.sh
```

The script validates the token with `getMe`, refuses a bot that has a webhook,
waits for you to message the bot so it can learn the chat and user id, encrypts
the token as a systemd credential, extends the drop-in, restarts and verifies.
Items marked *local approval only* are still announced but get no buttons: they
can only be approved in the UI.

### 4.6 Daily ledger anchor (recommended)

The audit chain detects edits, but a chain owner could in principle drop
records from the end and re-link. Anchors close that: a daily job records the
chain length and head somewhere the vault's own user cannot rewrite.

```sh
sudo install -m 0644 deploy/bsc-anchor.service deploy/bsc-anchor.timer /etc/systemd/system/
sudo install -d -m 0700 /var/lib/bsc-anchors
sudo systemctl daemon-reload && sudo systemctl enable --now bsc-anchor.timer
systemctl list-timers bsc-anchor.timer
```

If the ledger is ever truncated or rewritten, the unit fails and
`systemctl --failed` shows it. Point whatever already watches the host at that.

### 4.7 Upgrading

```sh
# 1. verify the new binary before it reaches the server
shasum -a 256 -c bsc-0.2.0-x86_64-unknown-linux-gnu.tar.gz.sha256

# 2. back up the vault (a consistent copy, while the daemon runs)
sudo python3 -c "import sqlite3;s=sqlite3.connect('file:/var/lib/bsc/vault.bsc?mode=ro',uri=True);d=sqlite3.connect('/var/lib/bsc/vault.backup.bsc');s.backup(d)"

# 3. install and restart
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo systemctl restart bsc

# 4. check
curl -s http://127.0.0.1:8787/v1/vault/status     # version, sealed, unattended_unseal
sudo bsc audit --vault /var/lib/bsc/vault.bsc     # ledger intact
```

A vault created by an older version is migrated automatically the first time a
newer binary opens it, in one transaction, and the migration is recorded in the
ledger. A file written by a *newer* version than the binary is refused rather
than damaged. Back up first anyway.

---

## 5. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Browser shows only `…` and nothing loads | The daemon is answering but a request is failing | `journalctl -u bsc -n 50` or the terminal running `bsc serve`; a version mismatch between binary and vault is the usual cause |
| `vault_sealed` from an agent | The daemon restarted | Unseal in the UI. Never give the passphrase to the agent |
| Remote browser refused | No `--public-origin`, or it does not match the URL | Set it to the exact origin, including `https://` |
| `bsc doctor` says auto-start missing | The service was never installed, or a different bind | `bsc service install --bind …` |
| Login refused after several tries | Login throttling, per client address | Wait, then try again; check for someone else guessing |
| `no such column` in the log | Binary older than the vault, or a failed migration | Install the matching binary; restore your backup if needed |
| Telegram buttons do nothing | Wrong chat, wrong user id, or an item marked local-only | Check the unit's `--telegram-chat` / `--telegram-user`; approve in the UI |

---

## 6. Rules that keep this safe

1. The passphrase is typed by a human, into the terminal or the UI. Never into
   a chat, a script, a ticket or a repository.
2. Agents get **tokens**, never the passphrase, and never a token pasted into a
   prompt. Tokens belong in configuration files.
3. The daemon stays on loopback. Exposure happens through a proxy you
   configured deliberately.
4. Back up the vault file, and keep at least one backup off the machine.
5. Never commit a vault, an export, a token or an anchor file. The repository
   holds source and documentation only.
