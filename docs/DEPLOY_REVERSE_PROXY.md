# Deploying behind a reverse proxy

**Status:** live since 2026-09-04 02:22 (UTC+8) at `https://sec.bastet.tw` on
the host `192.168.100.250` (Ubuntu 26.04, nginx 1.28): `bsc.service` active
and enabled as user `bsc`, vault created by the operator, daemon sealed until
the operator unseals it in the UI. Verified from another machine:
`/v1/vault/status` → `{"public_origin":"https://sec.bastet.tw","sealed":true}`,
document served with CSP and HSTS through Cloudflare, `bsc doctor
--url https://sec.bastet.tw` ✅ daemon / ✅ bind (acknowledged public origin) /
✅ web ui, and `bsc mcp --url https://sec.bastet.tw` answering in the error
contract over TLS. Two defects were found and fixed by that check: the binary
had no TLS backend at all, and `doctor` failed every non-loopback URL. Cloudflare proxies the hostname
(orange cloud) and reaches nginx through the site's public IP and a router
port-forward on 443 — **not** through the host's Cloudflare Tunnel, which
carries only `mizuki-line.bastet.tw` and, since this work, `ssh.bastet.tw`. This pulls the master plan's remote-exposure gate (§4.4) forward from
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

- Cloudflare's proxy connects to nginx on the public IP; nginx sees Cloudflare
  as `$remote_addr` and the real client in `CF-Connecting-IP`. The site config
  maps that into `X-Forwarded-For` and **overwrites** any inbound value, so a
  client cannot supply its own.
- Cloudflare terminates the public TLS and re-encrypts to nginx with the
  wildcard `*.bastet.tw` certificate, so `sec.bastet.tw` is only as private as
  the Cloudflare account — the same trade the rest of `bastet.tw` already
  makes.
- **The origin is directly reachable.** Anyone who knows the public IP can
  send `Host: sec.bastet.tw` straight to nginx on 443, bypassing Cloudflare
  (verified with `curl --resolve`). The vault's own authentication and
  throttle still apply, but Cloudflare-side controls (Access, WAF, rate
  limits) would not. Mitigation when wanted: restrict 443 on the router or
  host firewall to Cloudflare's published IP ranges, or move the hostname
  onto the tunnel and close the port-forward. Not done; recorded.
- The daemon does not know about Cloudflare; it knows one origin and one
  forwarded-for header.

## SSH over the same Cloudflare Tunnel (`ssh.bastet.tw`)

Requested alongside this deployment: reach the host's sshd through the
existing tunnel `d276e209-…`, allowed only from two IPs.
[`deploy/cloudflare-ssh-tunnel.sh`](../deploy/cloudflare-ssh-tunnel.sh) does
it idempotently through the API with a token read from a file:

1. **Tunnel ingress** — adds `ssh.bastet.tw → ssh://localhost:22` ahead of the
   catch-all, keeping the existing `mizuki-line.bastet.tw` rule. *Done.*
2. **DNS** — a proxied CNAME `ssh.bastet.tw → <tunnel-id>.cfargotunnel.com`.
   *Failed on the first run (token had Zone:Read but not DNS:Edit); created on
   the second run after the operator widened the token.*
3. **Access** — a self-hosted app of type `ssh` for the hostname with one
   policy, **Bypass** when the client IP is `172.216.48.153/32`,
   `59.124.17.34/32`, or `1.34.128.101/32` (the third added on request the
   same day). Everything else is denied at Cloudflare's edge before reaching
   the tunnel. *Done* (app `508fe70e-…`).

Client side, on an allow-listed machine with `cloudflared` installed:

```
Host ssh.bastet.tw
  ProxyCommand cloudflared access ssh --hostname %h
  User CatWhiskers
  IdentityFile ~/.ssh/<key>
```

sshd on the host already has `PasswordAuthentication no` and
`PubkeyAuthentication yes`, so the tunnel adds a network gate in front of an
already key-only service; it does not replace key auth. Port 22 remains open
on the LAN as before — closing it is a separate decision.

Verified both ways on 2026-09-04:

- **Denied** — before `1.34.128.101` was on the list, an HTTPS request from it
  to `ssh.bastet.tw` at the Cloudflare edge returned **403** from Access.
- **Allowed** — after adding it, `ssh -o ProxyCommand="cloudflared access ssh
  --hostname %h" CatWhiskers@ssh.bastet.tw` run *from the host itself* (whose
  egress is that same address) came back through Cloudflare and the tunnel:
  `TUNNEL-OK host=hermes-agent user=CatWhiskers`, and sshd logged `Accepted
  publickey for CatWhiskers from 127.0.0.1` — the connection arrives from
  `cloudflared` on loopback, as designed. The key was lent to the host for the
  test through a 10-minute agent forward, never copied.

**GUI clients without `ProxyCommand` (SecureCRT, PuTTY, MobaXterm…).** Run
`cloudflared` as a local listener and point the client at it:

```
cloudflared access tcp --hostname ssh.bastet.tw --url 127.0.0.1:2222
```

then connect the client to host `127.0.0.1`, port `2222`, protocol SSH2, user
`CatWhiskers`, public-key authentication with the same key. `cloudflared`
must be running while the session is open; on Windows a logon-triggered
scheduled task (`schtasks /Create /SC ONLOGON /TN "cloudflared ssh.bastet.tw"
/TR "\"C:\Program Files (x86)\cloudflared\cloudflared.exe\" access tcp
--hostname ssh.bastet.tw --url 127.0.0.1:2222"`) keeps it up. The Access
check happens at Cloudflare using the *client machine's* public IP, exactly
as with `ProxyCommand`. On first connection the client shows the host key of
`hermes-agent`; compare it with the fingerprints recorded below before
accepting.

Host key fingerprints of `hermes-agent` (read from `/etc/ssh` on the host on
2026-09-04; sshd offers all three):

```
ED25519  SHA256:fifrQkgqWKDW+V0E8KV0Dq7ILuOuhlcnr4GqbJR3LBQ   MD5:89:32:0d:73:6f:46:b3:92:68:32:b5:6f:79:71:b8:29
ECDSA    SHA256:29hLoIc4S816ss6ZD7ihy4qNQV9jseQKGkbhyUIBetE
RSA      SHA256:/wjFi9wpwwpGSMmfgbbG6qCFbVC+rr4ebsJLfADMFPQ
```

Client caveat: on a machine without an IPv6 default route, `cloudflared
access ssh` dials the edge's AAAA first and fails with `no route to host`
instead of falling back to A. The operator's Mac hit exactly this; the fix is
IPv6 connectivity on the client, not anything on the server. A plain HTTPS
`GET` to an `ssh`-type Access app returns 403 even from an allowed IP, so
`curl` is not a positive test for this app type — only `ssh` is.

## Not done

- No Cloudflare Access or allow-list (operator's choice, above).
- No mTLS between nginx and the daemon — both are on the same host and the
  daemon accepts only loopback peers.
- The system unit and nginx config are hand-written for this host;
  `bsc service install --system` does not exist yet.
- `bsc doctor` cannot check file permissions on a remote vault.
- The origin's direct reachability on the public IP (above) is not mitigated.
- The positive SSH test was observed from the host's own egress, not yet
  from `172.216.48.153` or `59.124.17.34`.
- The Cloudflare API token used for the setup should now be revoked or
  narrowed by the operator; it was read from a file and never printed.
