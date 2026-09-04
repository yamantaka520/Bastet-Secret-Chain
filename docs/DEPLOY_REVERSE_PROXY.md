# Deploying behind a reverse proxy

**Status:** validated on one production deployment. This document is the
recipe and the reasoning, with no site-specific detail in it: substitute your
own hostname for `secrets.example.com` throughout. Operational specifics of a
particular deployment — addresses, host names, allow-lists, tunnel or account
identifiers — do not belong in a public repository, and are not here.

## What changes when the daemon is exposed

The daemon still binds `127.0.0.1` only and still refuses any other bind. A
TLS-terminating proxy on the same host forwards to it. `bsc serve
--public-origin https://<host>` tells the daemon that this is the intended
arrangement, and only then:

| Behavior | Loopback only | With `--public-origin` |
| --- | --- | --- |
| `Origin` accepted on the human surface | `http://127.0.0.1:*`, `http://localhost:*` | those **plus** the one configured origin |
| Session cookie | `HttpOnly; SameSite=Strict` | same, **plus `Secure`** when the origin is https |
| Login throttle key | one bucket (everything is local) | first hop of `X-Forwarded-For` |
| Ledger | — | one `exposure_acknowledged` record at every start, with the origin |
| `/v1/vault/status` | — | shows `public_origin` |

The login throttle is 5 failed attempts per client per 10 minutes, after
which further attempts — right passphrase included — get `429 rate_limited`
for the rest of the window without running the KDF. Only the **first**
`X-Forwarded-For` hop is used, so later hops appended by a client cannot
evade it; and because nothing but the loopback proxy can reach the daemon,
the header cannot be forged by a remote peer. Without `--public-origin` the
header is ignored entirely.

Everything else is unchanged: agents still need a `bsct_` token, every read is
still ledgered, the reference URL still grants nothing.

## What is *not* protecting the login page

With the vault's own authentication as the only gate, the passphrase form is
reachable by anyone who can reach the hostname. The defenses are the Argon2id
cost (64 MiB / 3 passes per attempt), the two throttles (daemon and nginx),
`login denied` ledger records, and the fact that a passphrase never leaves the
form except over TLS. That is a defensible first step and it is what the
reference deployment started with, but the stronger options are worth taking:

- **An identity proxy** (Cloudflare Access, oauth2-proxy, your SSO) in front of
  the UI paths — `/`, `/assets/*`, `/v1/vault/*`, `/v1/items*`, `/v1/tokens*`,
  `/v1/sessions*`, `/v1/approvals*`, `/v1/audit*` — leaving the agent paths
  (`/v1/secrets*`, `/v1/access-requests*`, `/v1/token*`) to bearer tokens or a
  service token, since an agent cannot complete an interactive login.
- **An IP allow-list** in nginx for the UI paths, keyed on the real client
  address.

## Host layout

```
/usr/local/bin/bsc                          the release binary
/var/lib/bsc/                               0700, owner bsc:bsc
/var/lib/bsc/vault.bsc                      0600, created by the operator
/etc/systemd/system/bsc.service             deploy/bsc.service (system unit, User=bsc)
/etc/nginx/sites-available/<your-host>      deploy/nginx-bsc.conf
/etc/nginx/snippets/bsc-proxy.conf          deploy/nginx-bsc-proxy.snippet.conf
```

The vault is created by the operator, interactively, so the passphrase is
never in a transcript, a shell history, or an automation log:

```sh
sudo -u bsc /usr/local/bin/bsc init --vault /var/lib/bsc/vault.bsc
```

Then `sudo systemctl enable --now bsc`, `sudo nginx -t && sudo systemctl reload
nginx`, and from another machine `bsc doctor --url https://secrets.example.com`
(the vault checks are skipped when the file is not local; the daemon, UI, bind
and clock checks still run).

Why a **system** unit rather than `bsc service install`: the latter writes a
user unit, which on a server would need `loginctl enable-linger` and would run
as an interactive account. A dedicated `bsc` user with `ProtectSystem=strict`,
`ProtectHome=true` and a single `ReadWritePaths` is the right shape for a host
that runs other things.

## Unattended unseal

A server that restarts into a sealed vault is a server nobody can use until
someone opens the UI. `deploy/bsc-unattended.conf` is a drop-in that stores the
passphrase as a **systemd encrypted credential** (TPM2-sealed where the host
has one, otherwise sealed to the root-only host key) and passes it to the
daemon at start via `LoadCredentialEncrypted`; the daemon reads
`$CREDENTIALS_DIRECTORY/bsc-passphrase`, unseals, zeroizes, and writes
`unseal_unattended` (source `systemd-credential`) to the ledger. The operator
creates the credential once by typing the passphrase into
`systemd-creds encrypt` — it is never on a command line or in a file in the
clear. The trade is stated in the drop-in: root on the host can decrypt it, so
the vault is as private as the host. A wrong credential makes the unit fail
rather than start sealed, so a broken deployment is loud.

## Telegram approval channel (ADR 0005 §4)

`bsc serve --telegram-token-credential telegram-token --telegram-chat <chat id>
[--telegram-user <id>]…` turns on the outbound channel: at the third ladder
step (60 s) the daemon sends the pending approval — token label, item name,
the agent's reason verbatim, the deadline — to that one chat with ✅/⛔
buttons, and long-polls `getUpdates` for the press. Only that chat's buttons
are honoured, optionally only from the listed user ids; items flagged
🏠 local-approval-only are announced without buttons and a forged press is
refused. The decision is ledgered as `external:telegram:<user id>`, the
delivery as `approval_notified`. The bot token is a second systemd encrypted
credential (`LoadCredentialEncrypted=telegram-token:/etc/bsc/telegram.cred`);
`deploy/telegram-setup.sh` does the whole dance on the host — token typed
locally, validated, encrypted, chat and user id discovered from one message —
so the token is never on a command line.

## If a CDN or proxy network sits in front

- The proxy connects to nginx; nginx sees the proxy as `$remote_addr` and the
  real client in a provider header (`CF-Connecting-IP` for Cloudflare). The
  site config maps that into `X-Forwarded-For` and **overwrites** any inbound
  value, so a client cannot supply its own.
- If the provider terminates public TLS and re-encrypts to your origin with a
  wildcard certificate, the hostname is only as private as that provider
  account.
- **Check whether your origin is directly reachable.** If the origin's address
  is guessable and port 443 is open to the world, anyone can send
  `Host: secrets.example.com` straight to nginx and bypass every control the
  provider offers — Access, WAF, rate limits — leaving only the vault's own
  authentication and throttle. Verify with `curl --resolve`. Mitigate by
  restricting 443 to the provider's published ranges at the firewall, or by
  serving the hostname through an outbound tunnel and closing the inbound
  port. This is the most commonly missed step in this kind of deployment.
- The daemon knows nothing about any of this. It knows one origin and one
  forwarded-for header.

## Daily ledger anchor

`deploy/bsc-anchor.service` + `deploy/bsc-anchor.timer` run
`bsc audit --anchor-file /var/lib/bsc-anchors/anchors.jsonl` once a day as
root. The anchor directory is root-only, so the `bsc` service user — the only
identity that can write the vault — cannot rewrite the anchors to match a
truncated ledger. Install with the commands in the unit's header; check with
`systemctl list-timers bsc-anchor.timer` and `journalctl -u bsc-anchor`. An
inconsistent anchor makes the unit fail, which shows up in
`systemctl --failed`; wire that into whatever already watches the host.

## Not done

- No `bsc service install --system`: the system unit and nginx config are
  written by hand from the files in `deploy/`.
- No mTLS between nginx and the daemon — both are on the same host and the
  daemon accepts only loopback peers.
- `bsc doctor` cannot check file permissions on a remote vault.
