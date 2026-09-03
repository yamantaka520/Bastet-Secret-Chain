# AI Agent 接入手册

**适用版本：**Bastet Secret Chain 0.1.0
**语言：** [繁體中文](../zh-Hant/agents.md) · **简体中文** · [English](../en/agents.md) · [日本語](../ja/agents.md) · [한국어](../ko/agents.md)
**延伸阅读：**[安装手册](install.md) · [使用手册](guide.md) · [API 契约](../../API_CONTRACT.md)

这就是这个项目存在的理由：Agent 在需要的当下，精准取得它需要的那一份敏感数据，而敏感数据从不出现在提示词、URL、shell 历史或对话记录里。

---

## 1. 正确的接入长什么样

1. 由**人类**在 UI 签发一把有范围、有期限的 token，放进 Agent 的**配置文件**——不是提示词、不是仓库、不是 URL。
2. Agent 通过 **MCP server** 访问保险库，不是用 `curl`。
3. Agent 的指令明白要求：给出真实理由、遇到等待就等、永远不要叫人把敏感数据贴过来。
4. 人类在审计链看得到每一次读取，高价值的读取还会先进审批收件箱。

这四点少一点，即使跑得起来，接法也是错的。

为什么用 MCP 而不是裸 HTTP：工具描述是模型真的会读的规范；值不经过 shell；token 不会出现在 Agent 生成的命令里。HTTP API 仍然是唯一的真相来源与唯一的审计入口，供 CI 与不支持 MCP 的东西使用。

---

## 2. 接上一个 Agent

MCP server 就是同一个可执行文件：`bsc mcp` 以 stdio 与运行中的服务通信。给它一个网址，以及来自环境变量或 `0600` 文件的 token。

**Claude Code**——项目内的 `.mcp.json`（提交时**不要**含 token）或 `~/.claude.json`：

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

远程保险库就把网址换成 `"--url", "https://secrets.example.com"`。每个项目一组配置、各自一把窄范围 token：这样在 A 项目工作的 Agent，连 B 项目的条目都列不出来。

---

## 3. 六个工具

全部只读。没有任何工具可以新增、修改或删除——那些是人类在 UI 做的事。

| 工具 | 输入 | 结果 |
| --- | --- | --- |
| `list_secrets` | `path?`、`tag?` | 范围内的条目：引用、名称、路径、类型、标签、到期日、是否需审批。**永远不含值。** |
| `get_secret` | `sref`、`reason` | 值、版本、可能的警告——或 `approval_pending`。 |
| `request_access` | `sref`、`reason` | 一个可以等待的审批 id。 |
| `check_access` | `approval_id`、`wait_seconds?`（≤ 60） | 决定结果；批准时附上值，只给一次。 |
| `use_secret` | `sref`、`reason`、`url`、`method?`、`headers?`、`body?` | 上游服务的响应。凭据由服务注入，永远不会到 Agent 手上。 |
| `renew_access` | 无 | 把调用端 token 的到期时间往后延。永远不会扩大范围。 |

`reason` 是必填，而且会写进审计链。“用 commit abc123 部署 staging”是理由，“执行任务”不是。

---

## 4. 要对 Agent 说的话

把下面这段原封不动放进 `CLAUDE.md`、`AGENTS.md` 或等价的文件：

> 凭据一律来自 `bsc` MCP server。先用 `list_secrets` 找到条目，再用 `get_secret` 取用，`reason` 要写清楚你接下来要做什么。取回的值是活的：不要写进文件、不要打印出来、不要放进 shell 命令、不要在回复里复述。如果收到 `approval_pending`，就用 `check_access` 带 `wait_seconds: 60` 继续等——不要叫我把敏感数据贴给你，也不要把原本的调用重跑成循环。如果结果带有 token 即将到期的警告，在下一个自然段落调用 `renew_access`。如果条目设了使用绑定，优先用 `use_secret` 而不是读出值。

其中最重要的一句，是叫 Agent**不要**要求人把敏感数据贴过来。整套设计就是为了让那个失败模式不再发生。

---

## 5. 脚本与 CI

没有 MCP 客户端的场合就直接调用 HTTP API。Token 放在 CI 的 secret 存储区；理由放在 header，绝不放在 URL：

```sh
curl -fsS -H "Authorization: Bearer $BSC_TOKEN" \
     -H "X-BSC-Reason: deploy $GITHUB_SHA to staging" \
     "$BSC_URL/v1/secrets/$SREF" | jq -r .value
```

要处理三种响应：

- `200`——值在 `.value`（二进制在 `.value_base64`）。
- `202 approval_pending`——轮询审批直到有结果，遵守 `Retry-After`；遇到 `denied` 或 `timeout` 就写清楚日志并停止。
- `401 token_expired` 且 `renewable: true`——先 `POST /v1/token/renew`，再重试一次。

其他都是硬失败。把响应里的 `next_action` 打印出来，那句话就是写给看日志的人读的。

每条流水线用自己的 token，读取次数上限按工作量设置，寿命不长于它的调度周期。轮换的做法是签发新的、撤销旧的。

---

## 6. 错误代码

每个错误都带有机器可读的 `error`、给人看的 `message`、`next_action`，以及 `do_not`。最后一项存在的理由是：收到没有区别的 `401` 时 Agent 会自由发挥，而它最糟的发挥就是叫人把凭据贴进对话窗口。

| 代码 | HTTP | Agent 该怎么做 |
| --- | --- | --- |
| `approval_pending` | 202 | 用 `check_access` 等待。不要重跑成循环。 |
| `approval_denied` | 403 | 停下并报告。不要换个理由再问。 |
| `approval_timeout` | 408 | 报告没有人响应。不要循环。 |
| `token_expired` | 401 | 续期后重试一次。不要要求粘贴敏感数据。 |
| `token_revoked` | 401 | 停下，告诉用户要重新发一把。不要另寻来源。 |
| `scope_mismatch` | 403 | 说出自己需要什么。不要试探其他引用。 |
| `quota_exhausted` | 429 | 停下并告知用户。 |
| `rate_limited` | 429 | 等 `retry_after` 秒。不要把循环缩得更紧。 |
| `vault_sealed` | 503 | 说明需要人到 UI 解封。**绝不**索取保险库口令。 |
| `not_found` | 404 | 用 `list_secrets` 重新确认。不要猜引用。 |
| `reason_required` | 400 | 带着具体理由重新调用。不要用占位字符串。 |
| `use_not_configured` | 400 | 请人为该条目配置绑定；若真的需要值，才改用读取。 |
| `use_not_allowed` | 403 | 说出自己需要哪个 URL。不要试探其他 URL。 |
| `upstream_failed` | 502 | 重试一次后报告。不要为了自己调用服务而索取敏感数据。 |

---

## 7. 出问题时

| Agent 说 | 代表 | 你该做 |
| --- | --- | --- |
| “unauthorized” | token 不被认得 | 检查 `BSC_TOKEN`、`--token-file`、网址 |
| “token_expired, renewable: false” | 已过续期窗口 | 到 UI 签发一把新的 |
| “scope_mismatch” | 保险库对了，token 不对 | 放宽范围，或为该路径签发一把 |
| “approval_pending”很久 | 没有人审批 | 打开收件箱；下次考虑先开任务窗口 |
| “vault_sealed” | 服务重启过 | 到 UI 解封。绝不能让 Agent 知道口令 |
| 它请你把敏感数据贴过去 | 它没有遵守指令 | 拒绝。并确认它真的走 `bsc mcp`，不是某个 shell 工具 |

---

## 8. 反模式

- 把 `bsct_…` token 放进提示词、`CLAUDE.md`、提交进 git 的 `.env`，或 URL。Token 是凭据，就要当凭据对待。
- 所有 Agent 共用一把大范围 token。范围正是审计链有没有价值的关键。
- 明明有 MCP，却让 Agent 用 shell 工具 `curl` 打 API：值会落进进程参数与 shell 历史。
- 为了让流水线安静一点，把服务账户的审批关掉。改用任务窗口或预先授权，两者都会自己结束。
- “就这一次”把敏感数据贴出来以解开卡住的流程。那正是这套系统存在的目的——让那件事不必发生。
