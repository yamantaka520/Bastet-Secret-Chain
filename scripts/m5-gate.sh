#!/usr/bin/env bash
# M5 gate: a real agent completes a multi-step task through `bsc mcp`, crossing
# a token renewal and a human approval. Requires a running daemon, a human
# session cookie jar, and a logged-in `claude` CLI.
#
#   scripts/m5-gate.sh http://127.0.0.1:8797 /path/to/cookie-jar /path/to/bsc-binary
#
# What it does: creates an approval-required service-account item, mints a
# 100 s token scoped to it, waits until the token is expired-but-renewable,
# starts a "human" that approves the first inbox entry after 8 s, then runs
# `claude -p` with the MCP server and prints the tool calls the agent made,
# the approver's log, and the item's ledger.
set -euo pipefail
B="${1:?daemon url}"; J="${2:?cookie jar}"; BSC="${3:?bsc binary}"
W=$(mktemp -d)
human() { curl -s -b "$J" -H 'X-BSC-Client: cli' "$@"; }

SREF=$(human -H 'Content-Type: application/json' -d '{"path":"prod/m5","name":"m5-gate-service-account","type":"service_account","tags":["m5"],"env":"prod","value":"{\"type\":\"service_account\",\"project_id\":\"m5-gate-project\",\"private_key_id\":\"fake\"}"}' "$B/v1/items" | python3 -c 'import sys,json; print(json.load(sys.stdin)["sref"])')
TOK=$(human -H 'Content-Type: application/json' -d '{"label":"claude-code-m5","scope":{"paths":["prod/m5"]},"lifetime":100,"max_lifetime":3600}' "$B/v1/tokens" | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')
echo "item $SREF; token minted; waiting 105 s so it is expired but renewable"
cat > "$W/mcp.json" <<JSON
{ "mcpServers": { "bsc": { "command": "$BSC", "args": ["mcp", "--url", "$B"], "env": { "BSC_TOKEN": "$TOK" } } } }
JSON
chmod 600 "$W/mcp.json"
sleep 105
( for _ in $(seq 1 80); do sleep 3; A=$(human "$B/v1/approvals" | python3 -c 'import sys,json; a=json.load(sys.stdin)["approvals"]; print(a[0]["id"] if a else "")'); if [ -n "$A" ]; then sleep 8; human -X POST "$B/v1/approvals/$A/approve" >/dev/null && echo "[human] approved $A at $(date +%T)"; break; fi; done ) > "$W/approver.log" 2>&1 &

echo "=== claude -p at $(date +%T) ==="
set +e
claude -p "You have the bsc MCP server. Task: find the item named m5-gate-service-account with list_secrets, then read it with get_secret using the reason 'M5 gate test: deploy build 1 to Firebase'. If a result says the token expired but is renewable, call renew_access and retry. If a result is approval_pending, call check_access with wait_seconds 60 and keep waiting until it is approved, denied, or timed out. When you have the value, reply with ONLY the project_id field from the JSON and nothing else. Never print the whole value." \
  --mcp-config "$W/mcp.json" --allowedTools "mcp__bsc__list_secrets,mcp__bsc__get_secret,mcp__bsc__request_access,mcp__bsc__check_access,mcp__bsc__renew_access" \
  --output-format stream-json --verbose --max-turns 20 < /dev/null > "$W/run.jsonl" 2> "$W/run.err"
echo "claude exit $?"
set -e
python3 - "$W/run.jsonl" <<'PY'
import sys,json
final=None
for line in open(sys.argv[1]):
    try: m=json.loads(line)
    except: continue
    if m.get("type")=="assistant":
        for c in m["message"].get("content",[]):
            if c.get("type")=="tool_use": print(f"→ {c['name']:24} {json.dumps(c.get('input',{}))[:100]}")
            elif c.get("type")=="text" and c["text"].strip(): print(f"  [assistant] {c['text'].strip()[:100]}")
    if m.get("type")=="user":
        for c in m["message"].get("content",[]):
            if c.get("type")=="tool_result":
                txt=c.get("content")
                if isinstance(txt,list): txt=" ".join(x.get("text","") for x in txt if isinstance(x,dict))
                s=str(txt)
                tag=[k for k in ["token_expired","approval_pending","\"status\": \"pending\"","\"status\": \"approved\"","\"status\": \"consumed\"","renewable_until","project_id","\"items\"","daemon_unreachable"] if k in s]
                print(f"  ← {', '.join(tag) if tag else s[:80]}")
    if m.get("type")=="result": final=m.get("result"); print(f"  [turns={m.get('num_turns')} duration={m.get('duration_ms',0)/1000:.0f}s]")
print("=== final answer ==="); print(final)
PY
echo "=== approver ==="; cat "$W/approver.log"
echo "=== ledger for the item ==="; human "$B/v1/audit?subject=$SREF&limit=50" | python3 -c 'import sys,json; [print(r["ts"][11:19], r["actor"], r["action"], r["outcome"], r["meta"].get("reason","")) for r in json.load(sys.stdin)["records"]]'
echo "=== renewals ==="; human "$B/v1/audit?limit=1000" | python3 -c 'import sys,json; [print(r["ts"][11:19], r["action"], r["outcome"], r["subject"]) for r in json.load(sys.stdin)["records"] if r["action"]=="token_renewed"]'
echo "=== stderr tail ==="; tail -3 "$W/run.err"
rm -rf "$W"
