# AI Agent 接入手冊

**適用版本：**Bastet Secret Chain 0.2.0
**語言：** **繁體中文** · [简体中文](../zh-Hans/agents.md) · [English](../en/agents.md) · [日本語](../ja/agents.md) · [한국어](../ko/agents.md)
**延伸閱讀：**[安裝手冊](install.md) · [使用手冊](guide.md) · [API 契約](../../API_CONTRACT.md)

這就是這個專案存在的理由：Agent 在需要的當下，精準取得它需要的那一份秘密，而秘密從不出現在提示詞、URL、shell 歷史或對話紀錄裡。

---

## 1. 正確的接入長什麼樣

1. 由**人類**在 UI 鑄造一把有範圍、有期限的 token，放進 Agent 的**設定檔**——不是提示詞、不是版本庫、不是 URL。
2. Agent 透過 **MCP server** 存取保險庫，不是用 `curl`。
3. Agent 的指示明白要求：給出真實理由、遇到等待就等、永遠不要叫人把秘密貼過來。
4. 人類在稽核鏈看得到每一次讀取，高價值的讀取還會先進核准收件匣。

這四點少一點，即使跑得起來，接法也是錯的。

為什麼用 MCP 而不是裸 HTTP：工具描述是模型真的會讀的規格；值不經過 shell；token 不會出現在 Agent 產生的指令裡。HTTP API 仍然是唯一的真相來源與唯一的稽核入口，供 CI 與不支援 MCP 的東西使用。

---

## 2. 接上一個 Agent

MCP server 就是同一支執行檔：`bsc mcp` 以 stdio 與執行中的服務溝通。給它一個網址，以及來自環境變數或 `0600` 檔案的 token。

**Claude Code**——專案內的 `.mcp.json`（提交時**不要**含 token）或 `~/.claude.json`：

```json
{
  "mcpServers": {
    "bsc": {
      "command": "bsc",
      "args": ["mcp", "--url", "http://127.0.0.1:8787"],
      "env": { "BSC_TOKEN": "${BSC_TOKEN}" }
    }
  }
}
```

**Codex CLI**——`~/.codex/config.toml`：

```toml
[mcp_servers.bsc]
command = "bsc"
args = ["mcp", "--url", "http://127.0.0.1:8787", "--token-file", "/home/you/.bsc/tokens/codex"]
```

**Gemini CLI／Agy**——`~/.gemini/settings.json`：

```json
{ "mcpServers": { "bsc": { "command": "bsc", "args": ["mcp"], "env": { "BSC_TOKEN": "$BSC_TOKEN" } } } }
```

遠端保險庫就把網址換成 `"--url", "https://secrets.example.com"`。每個專案一組設定、各自一把窄範圍 token：這樣在 A 專案工作的 Agent，連 B 專案的項目都列不出來。

---

## 3. 六個工具

全部唯讀。沒有任何工具可以新增、修改或刪除——那些是人類在 UI 做的事。

| 工具 | 輸入 | 結果 |
| --- | --- | --- |
| `list_secrets` | `path?`、`tag?` | 範圍內的項目：參照、名稱、路徑、類型、標籤、到期日、是否需核准。**永遠不含值。** |
| `get_secret` | `sref`、`reason` | 值、版本、可能的警告——或 `approval_pending`。 |
| `request_access` | `sref`、`reason` | 一個可以等待的核准 id。 |
| `check_access` | `approval_id`、`wait_seconds?`（≤ 60） | 決定結果；核准時附上值，只給一次。 |
| `use_secret` | `sref`、`reason`、`url`、`method?`、`headers?`、`body?` | 上游服務的回應。憑證由服務注入，永遠不會到 Agent 手上。 |
| `renew_access` | 無 | 把呼叫端 token 的到期時間往後延。永遠不會擴大範圍。 |

`reason` 是必填，而且會寫進稽核鏈。「用 commit abc123 部署 staging」是理由，「執行任務」不是。

---

## 4. 要對 Agent 說的話

把下面這段原封不動放進 `CLAUDE.md`、`AGENTS.md` 或等價的檔案：

> 憑證一律來自 `bsc` MCP server。先用 `list_secrets` 找到項目，再用 `get_secret` 取用，`reason` 要寫清楚你接下來要做什麼。取回的值是活的：不要寫進檔案、不要印出來、不要放進 shell 指令、不要在回覆裡複述。如果收到 `approval_pending`，就用 `check_access` 帶 `wait_seconds: 60` 繼續等——不要叫我把秘密貼給你，也不要把原本的呼叫重跑成迴圈。如果結果帶有 token 即將到期的警告，在下一個自然段落呼叫 `renew_access`。如果項目設了使用綁定，優先用 `use_secret` 而不是讀出值。

其中最重要的一句，是叫 Agent**不要**要求人把秘密貼過來。整套設計就是為了讓那個失敗模式不再發生。

---

## 5. 腳本與 CI

沒有 MCP 客戶端的場合就直接呼叫 HTTP API。Token 放在 CI 的 secret 儲存區；理由放在 header，絕不放在 URL：

```sh
curl -fsS -H "Authorization: Bearer $BSC_TOKEN" \
     -H "X-BSC-Reason: deploy $GITHUB_SHA to staging" \
     "$BSC_URL/v1/secrets/$SREF" | jq -r .value
```

要處理三種回應：

- `200`——值在 `.value`（二進位在 `.value_base64`）。
- `202 approval_pending`——輪詢核准直到有結果，遵守 `Retry-After`；遇到 `denied` 或 `timeout` 就寫清楚記錄並停止。
- `401 token_expired` 且 `renewable: true`——先 `POST /v1/token/renew`，再重試一次。

其他都是硬失敗。把回應裡的 `next_action` 印出來，那句話就是寫給看記錄的人讀的。

每條流水線用自己的 token，讀取次數上限依工作量設定，壽命不長於它的排程週期。輪替的做法是鑄新的、撤舊的。

---

## 6. 錯誤代碼

每個錯誤都帶有機器可判讀的 `error`、給人看的 `message`、`next_action`，以及 `do_not`。最後一項存在的理由是：收到沒有區別的 `401` 時 Agent 會自己發揮，而它最糟的發揮就是叫人把憑證貼進對話視窗。

| 代碼 | HTTP | Agent 該怎麼做 |
| --- | --- | --- |
| `approval_pending` | 202 | 用 `check_access` 等待。不要重跑成迴圈。 |
| `approval_denied` | 403 | 停下並回報。不要換個理由再問。 |
| `approval_timeout` | 408 | 回報沒有人回應。不要迴圈。 |
| `token_expired` | 401 | 續期後重試一次。不要要求貼上秘密。 |
| `token_revoked` | 401 | 停下，告訴使用者要重新發一把。不要另尋來源。 |
| `scope_mismatch` | 403 | 說出自己需要什麼。不要試探其他參照。 |
| `quota_exhausted` | 429 | 停下並告知使用者。 |
| `rate_limited` | 429 | 等 `retry_after` 秒。不要把迴圈縮得更緊。 |
| `vault_sealed` | 503 | 說明需要人到 UI 解封。**絕不**索取保險庫密語。 |
| `not_found` | 404 | 用 `list_secrets` 重新確認。不要猜參照。 |
| `reason_required` | 400 | 帶著具體理由重新呼叫。不要用佔位字串。 |
| `use_not_configured` | 400 | 請人為該項目設定綁定；若真的需要值，才改用讀取。 |
| `use_not_allowed` | 403 | 說出自己需要哪個 URL。不要試探其他 URL。 |
| `upstream_failed` | 502 | 重試一次後回報。不要為了自己呼叫服務而索取秘密。 |

---

## 7. 出問題時

| Agent 說 | 代表 | 你該做 |
| --- | --- | --- |
| 「unauthorized」 | token 不被認得 | 檢查 `BSC_TOKEN`、`--token-file`、網址 |
| 「token_expired, renewable: false」 | 已過續期窗口 | 到 UI 鑄一把新的 |
| 「scope_mismatch」 | 保險庫對了，token 不對 | 放寬範圍，或為該路徑鑄一把 |
| 「approval_pending」很久 | 沒有人核准 | 打開收件匣；下次考慮先開任務窗口 |
| 「vault_sealed」 | 服務重啟過 | 到 UI 解封。絕不能讓 Agent 知道密語 |
| 它請你把秘密貼過去 | 它沒有遵守指示 | 拒絕。並確認它真的走 `bsc mcp`，不是某個 shell 工具 |

---

## 8. 反模式

- 把 `bsct_…` token 放進提示詞、`CLAUDE.md`、提交進 git 的 `.env`，或 URL。Token 是憑證，就要當憑證對待。
- 所有 Agent 共用一把大範圍 token。範圍正是稽核鏈有沒有價值的關鍵。
- 明明有 MCP，卻讓 Agent 用 shell 工具 `curl` 打 API：值會落進行程參數與 shell 歷史。
- 為了讓流水線安靜一點，把服務帳戶的核准關掉。改用任務窗口或預先授權，兩者都會自己結束。
- 「就這一次」把秘密貼出來以解開卡住的流程。那正是這套系統存在的目的——讓那件事不必發生。
