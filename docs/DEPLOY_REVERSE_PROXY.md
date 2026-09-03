# Deploying behind a reverse proxy

**Status:** first done on 2026-09-04 for `https://sec.bastet.tw` on the host
`192.168.100.250` (Ubuntu 26.04, nginx 1.28, Cloudflare Tunnel already in
place). This pulls the master plan's remote-exposure gate (§4.4) forward from
M6/M7 at the operator's request; what was implemented and what was not is
listed at the end.

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
form except over TLS. This is the arrangement the operator chose for
`sec.bastet.tw` on 2026-09-04 as a first step. The stronger options remain
available and are recommended:

- **Cloudflare Access** in front of the UI paths (`/`, `/assets/*`,
  `/v1/vault/*`, `/v1/items*`, `/v1/tokens*`, `/v1/sessions*`,
  `/v1/approvals*`, `/v1/audit*`), leaving the agent paths
  (`/v1/secrets*`, `/v1/access-requests*`, `/v1/token*`) to bearer tokens or
  an Access service token. The operator already runs a tunnel, so this is
  dashboard work rather than new infrastructure.
- **An IP allow-list** in nginx keyed on `CF-Connecting-IP` for the UI paths.

## Host layout used

```
/usr/local/bin/bsc                  the release binary (from the CI artifact)
/var/lib/bsc/                       0700, owner bsc:bsc
/var/lib/bsc/vault.bsc              0600, created by the operator with `bsc init`
/etc/systemd/system/bsc.service     deploy/bsc.service (system unit, User=bsc)
/etc/nginx/sites-available/sec.bastet.tw   deploy/nginx-sec.bastet.tw.conf
/etc/nginx/snippets/bsc-proxy.conf         deploy/nginx-bsc-proxy.snippet.conf
```

The vault is created by the operator, interactively, so the passphrase is
never in a transcript, a shell history, or an automation log:

```sh
sudo -u bsc /usr/local/bin/bsc init --vault /var/lib/bsc/vault.bsc
```

Then `sudo systemctl enable --now bsc`, `sudo nginx -t && sudo systemctl reload
nginx`, and from anywhere: `bsc doctor --url https://sec.bastet.tw` (the vault
checks are skipped when the file is not local; the daemon, UI, bind, and
clock checks still run).

Why a **system** unit rather than `bsc service install`: the latter writes a
user unit, which on a server would need `loginctl enable-linger` and would
run as an interactive account. A dedicated `bsc` user with `ProtectSystem=
strict`, `ProtectHome=true`, and a single `ReadWritePaths` is the right shape
for a host that runs other things.

## Cloudflare specifics

- The tunnel forwards to nginx; nginx sees the client as the tunnel's
  loopback address and the real client in `CF-Connecting-IP`. The site config
  maps that into `X-Forwarded-For` and **overwrites** any inbound value, so a
  client cannot supply its own.
- Because the tunnel terminates the public TLS at Cloudflare, `sec.bastet.tw`
  is only as private as the Cloudflare account. That is the trade the operator
  accepted by using the tunnel for the rest of `bastet.tw` already.
- The daemon does not know about Cloudflare; it knows one origin and one
  forwarded-for header.

## Not done

- No Cloudflare Access or allow-list (operator's choice, above).
- No mTLS between nginx and the daemon — both are on the same host and the
  daemon accepts only loopback peers.
- The system unit and nginx config are hand-written for this host;
  `bsc service install --system` does not exist yet.
- `bsc doctor` cannot check file permissions on a remote vault.
