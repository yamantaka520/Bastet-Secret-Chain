#!/usr/bin/env bash
# Enable the Telegram approval channel for a systemd-managed bsc daemon.
#
# Run this ON THE HOST as a sudo-capable user. The bot token is typed into this
# terminal only: it is validated against the Bot API, encrypted with
# systemd-creds into /etc/bsc/telegram.cred, and never written in plaintext.
# The chat id and your Telegram user id are discovered from a message you send
# to the bot while the script waits. The existing drop-in's ExecStart is then
# extended with --telegram-token-credential / --telegram-chat / --telegram-user.
set -euo pipefail

DROPIN=/etc/systemd/system/bsc.service.d/unattended.conf
CRED=/etc/bsc/telegram.cred
API=${TELEGRAM_API_BASE:-https://api.telegram.org}

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need curl; need python3; need systemd-creds
[ -f "$DROPIN" ] || { echo "$DROPIN not found; set up unattended unseal first" >&2; exit 1; }

read -rsp "Telegram bot token (from @BotFather, never pasted anywhere else): " TOK; echo
[[ "$TOK" == *:* ]] || { echo "that does not look like a bot token" >&2; exit 1; }

# 1. Validate the token and refuse a bot that has a webhook (getUpdates would fail).
me=$(curl -sS -m 20 "$API/bot$TOK/getMe")
python3 - "$me" <<'PY'
import json,sys
r=json.loads(sys.argv[1])
if not r.get("ok"): sys.exit("getMe failed: %s" % r.get("description"))
print("bot: @%s (id %s)" % (r["result"]["username"], r["result"]["id"]))
PY
wh=$(curl -sS -m 20 "$API/bot$TOK/getWebhookInfo")
python3 - "$wh" <<'PY'
import json,sys
r=json.loads(sys.argv[1])
if r.get("ok") and r["result"].get("url"):
    sys.exit("bot has a webhook set (%s); remove it first: deleteWebhook" % r["result"]["url"])
PY

# 2. Discover chat id and user id from a fresh message.
echo
echo "Now open Telegram and send any message (e.g. /start) to the bot. Waiting up to 120 s…"
found=""
for _ in $(seq 1 24); do
  upd=$(curl -sS -m 20 "$API/bot$TOK/getUpdates?timeout=5&allowed_updates=%5B%22message%22%5D")
  found=$(python3 - "$upd" <<'PY'
import json,sys
r=json.loads(sys.argv[1])
if not r.get("ok"): sys.exit(0)
for u in reversed(r.get("result",[])):
    m=u.get("message")
    if m and m.get("from"):
        print("%d %d %d %s" % (m["chat"]["id"], m["from"]["id"], u["update_id"], m["chat"].get("type","")))
        break
PY
)
  [ -n "$found" ] && break
done
[ -n "$found" ] || { echo "no message received; run again" >&2; exit 1; }
read -r CHAT UID_ UPD CTYPE <<<"$found"
echo "chat id: $CHAT ($CTYPE)   your user id: $UID_"
# Acknowledge the update so the daemon does not replay it.
curl -sS -m 20 "$API/bot$TOK/getUpdates?offset=$((UPD+1))&timeout=0" >/dev/null

# 3. Encrypt the token as a systemd credential (root only).
printf '%s' "$TOK" | sudo systemd-creds encrypt --name=telegram-token - "$CRED"
unset TOK
sudo chmod 0600 "$CRED"

# 4. Extend the drop-in: add the credential line and the flags to ExecStart.
sudo python3 - "$DROPIN" "$CRED" "$CHAT" "$UID_" <<'PY'
import re,sys
p,cred,chat,uid=sys.argv[1:]
s=open(p).read()
if f"LoadCredentialEncrypted=telegram-token:{cred}" not in s:
    s=re.sub(r"(LoadCredentialEncrypted=bsc-passphrase:[^\n]*\n)",
             r"\1"+f"LoadCredentialEncrypted=telegram-token:{cred}\n", s, 1)
lines=s.split("\n")
for i,l in enumerate(lines):
    if l.startswith("ExecStart=/"):
        l=re.sub(r"\s--telegram-(token-credential|token-file|chat|user)\s+\S+","",l)
        lines[i]=l+f" --telegram-token-credential telegram-token --telegram-chat {chat} --telegram-user {uid}"
open(p,"w").write("\n".join(lines))
print(open(p).read())
PY

# 5. Restart and verify.
sudo systemctl daemon-reload
sudo systemctl restart bsc
sleep 3
systemctl is-active bsc
curl -s http://127.0.0.1:8790/v1/vault/status; echo
sudo journalctl -u bsc -n 6 --no-pager -o cat | sed 's/\x1b\[[0-9;]*m//g' | grep -iE "telegram|unsealed|error" || true
echo "done. The bot will message chat $CHAT at ladder step 3 for approval-required items; only user $UID_ may press ✅/⛔."
