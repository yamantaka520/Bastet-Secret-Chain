#!/usr/bin/env bash
# Publish SSH on an existing remotely-managed Cloudflare Tunnel, restricted to
# an IP allow-list with a Cloudflare Access Bypass policy.
#
#   CF_TOKEN_FILE=~/Documents/SSH-Key/cloudflare-bastet.token \
#   deploy/cloudflare-ssh-tunnel.sh <account_id> <tunnel_id> <zone_name> <hostname> <ip1,ip2,...>
#
# What it does, idempotently:
#   1. GET the tunnel's remote configuration and add an ingress rule
#      <hostname> -> ssh://localhost:22 ahead of the catch-all (keeps the rest).
#   2. Upsert a proxied DNS CNAME <hostname> -> <tunnel_id>.cfargotunnel.com.
#   3. Upsert an Access self-hosted application for <hostname> with one policy:
#      Bypass when the client IP is in the list. Everything else is denied.
# The token is read from a file and never printed. Required token permissions:
#   Account: Cloudflare Tunnel: Edit, Access: Apps and Policies: Edit
#   Zone <zone_name>: DNS: Edit, Zone: Read
set -euo pipefail
ACCOUNT="${1:?account_id}"; TUNNEL="${2:?tunnel_id}"; ZONE_NAME="${3:?zone}"; HOST="${4:?hostname}"; IPS="${5:?ip list}"
TOKEN_FILE="${CF_TOKEN_FILE:?set CF_TOKEN_FILE}"
[ -r "$TOKEN_FILE" ] || { echo "cannot read $TOKEN_FILE" >&2; exit 2; }
TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
API=https://api.cloudflare.com/client/v4
cf() { curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
ok() { python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get("success") else (print(json.dumps(d.get("errors"),ensure_ascii=False),file=sys.stderr) or 1))'; }

echo "== token check =="
cf "$API/user/tokens/verify" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["result"]["status"] if d.get("success") else d)'

echo "== 1. tunnel ingress =="
CUR=$(cf "$API/accounts/$ACCOUNT/cfd_tunnel/$TUNNEL/configurations")
echo "$CUR" | ok
NEW=$(echo "$CUR" | python3 -c '
import sys,json
d=json.load(sys.stdin)["result"]["config"] or {}
ing=[r for r in d.get("ingress",[]) if r.get("hostname")!="'"$HOST"'"]
tail=[r for r in ing if "hostname" not in r]
rest=[r for r in ing if "hostname" in r]
rule={"hostname":"'"$HOST"'","service":"ssh://localhost:22"}
d["ingress"]=rest+[rule]+(tail or [{"service":"http_status:404"}])
print(json.dumps({"config":d}))')
echo "$NEW" | python3 -c 'import sys,json; [print("  ", r.get("hostname","<catch-all>"), "->", r["service"]) for r in json.load(sys.stdin)["config"]["ingress"]]'
cf -X PUT "$API/accounts/$ACCOUNT/cfd_tunnel/$TUNNEL/configurations" --data "$NEW" | ok && echo "  ingress updated"

echo "== 2. DNS CNAME =="
ZONE=$(cf "$API/zones?name=$ZONE_NAME" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"][0]["id"])')
REC=$(cf "$API/zones/$ZONE/dns_records?name=$HOST" | python3 -c 'import sys,json; r=json.load(sys.stdin)["result"]; print(r[0]["id"] if r else "")')
BODY=$(printf '{"type":"CNAME","name":"%s","content":"%s.cfargotunnel.com","proxied":true,"ttl":1,"comment":"bsc: ssh over cloudflare tunnel"}' "$HOST" "$TUNNEL")
if [ -n "$REC" ]; then cf -X PUT "$API/zones/$ZONE/dns_records/$REC" --data "$BODY" | ok && echo "  CNAME updated"; else cf -X POST "$API/zones/$ZONE/dns_records" --data "$BODY" | ok && echo "  CNAME created"; fi

echo "== 3. Access application + Bypass-by-IP policy =="
IPJSON=$(python3 -c 'import sys,json; print(json.dumps([{"ip":{"ip": (i if "/" in i else i+"/32")}} for i in sys.argv[1].split(",") if i.strip()]))' "$IPS")
APP=$(cf "$API/accounts/$ACCOUNT/access/apps" | python3 -c 'import sys,json; r=[a for a in json.load(sys.stdin)["result"] or [] if a.get("domain")=="'"$HOST"'"]; print(r[0]["id"] if r else "")')
APPBODY=$(printf '{"name":"SSH %s","domain":"%s","type":"ssh","session_duration":"24h","app_launcher_visible":false,"allow_authenticate_via_warp":false,"auto_redirect_to_identity":false}' "$HOST" "$HOST")
if [ -n "$APP" ]; then cf -X PUT "$API/accounts/$ACCOUNT/access/apps/$APP" --data "$APPBODY" | ok && echo "  app updated ($APP)"; else APP=$(cf -X POST "$API/accounts/$ACCOUNT/access/apps" --data "$APPBODY" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["result"]["id"]) if d.get("success") else (print(d,file=sys.stderr) or sys.exit(1))'); echo "  app created ($APP)"; fi
POLBODY=$(printf '{"name":"allow-list IPs bypass","decision":"bypass","precedence":1,"include":%s,"exclude":[],"require":[]}' "$IPJSON")
POL=$(cf "$API/accounts/$ACCOUNT/access/apps/$APP/policies" | python3 -c 'import sys,json; r=[p for p in json.load(sys.stdin)["result"] or [] if p.get("name")=="allow-list IPs bypass"]; print(r[0]["id"] if r else "")')
if [ -n "$POL" ]; then cf -X PUT "$API/accounts/$ACCOUNT/access/apps/$APP/policies/$POL" --data "$POLBODY" | ok && echo "  policy updated"; else cf -X POST "$API/accounts/$ACCOUNT/access/apps/$APP/policies" --data "$POLBODY" | ok && echo "  policy created"; fi
echo "  bypass for: $IPS ; everyone else is denied by Access"
echo
echo "client side (on an allow-listed machine, with cloudflared installed):"
echo "  Host $HOST"
echo "    ProxyCommand cloudflared access ssh --hostname %h"
echo "    User <user>"
echo "    IdentityFile ~/.ssh/<key>"
