# 安装手册

**适用版本：**Bastet Secret Chain 0.1.0 · macOS、Windows、Linux
**语言：** [繁體中文](../zh-Hant/install.md) · **简体中文** · [English](../en/install.md) · [日本語](../ja/install.md) · [한국어](../ko/install.md)
**延伸阅读：**[使用手册](guide.md) · [Agent 接入手册](agents.md)

整套系统只有一个文件。`bsc` 这个可执行文件同时是命令行工具、常驻服务、Web 服务器，Web UI 也内嵌在里面。不必安装运行时，不必搭数据库，不必用容器。保险库是一个 SQLite 文件，只有你解得开。

---

## 1. 开始之前

| 你需要 | 原因 |
| --- | --- |
| 一句你记得住、而且从没在别处用过的口令 | 所有加密密钥都由它派生。没有人能替你重置——维护者不行、系统管理员不行、AI 助手也不行。 |
| 60 MB 磁盘空间 | 可执行文件加保险库。 |
| 一个终端 | 安装与第一次创建保险库要用命令行。之后的操作都在 Web UI。 |

**口令绝对不要让别人生成或看见，包括正在帮你安装的 AI 助手。** 自己在自己的终端或 Web UI 里输入。只要曾经出现在对话窗口里，就当作已经泄露，立刻更换。

---

## 2. 选择你的安装形态

- **个人电脑**——保险库跑在你的笔记本上，只监听 `127.0.0.1`，同一台机器上的 Agent 才用得到。请看第 3 节。
- **共享服务器**——保险库跑在 Linux 主机上，前面摆一台 TLS 反向代理，让多个人与远程 Agent 都能访问。请看第 4 节。服务器上仍要先做完第 3 节，第 4 节取代其中的自动启动与对外开放部分。

---

## 3. 个人电脑

### 3.1 安装可执行文件

**方式 A——安装脚本（推荐）。** 运行前请先读过脚本；它不是设计来从网络直接管进 shell 的。

```sh
# macOS 与 Linux
curl -fsSLO https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.sh
less install.sh          # 先读一遍
sh install.sh v0.1.0
```

```powershell
# Windows
Invoke-WebRequest -Uri https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.ps1 -OutFile install.ps1
notepad install.ps1      # 先读一遍
.\install.ps1 -Version v0.1.0
```

脚本会下载对应平台的压缩包，比对同一份 release 发布的 `SHA256SUMS`，然后把 `bsc` 装到 `~/.local/bin`（macOS、Linux）或 `%LOCALAPPDATA%\Programs\bsc`（Windows）。如果脚本提醒你，把该目录加进 `PATH`。

这个比对能证明文件在传输过程中没被损坏或替换，但**不能**证明是谁构建的——因为哈希值和文件来自同一个发布页。要验证来源，再验一次构建来源证明：

```sh
gh attestation verify bsc-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo yamantaka520/Bastet-Secret-Chain
```

发布的可执行文件目前**还没有**用项目密钥签名，这排在下一个里程碑，[`SECURITY.md`](../../../SECURITY.md) 有明白写出来。

**方式 B——从源码构建。** 需要 Rust（stable）与 Node.js 22。

```sh
git clone https://github.com/yamantaka520/Bastet-Secret-Chain
cd Bastet-Secret-Chain
npm --prefix ui ci && npm --prefix ui run build   # 构建 Web UI
cargo install --path crates/bsc --locked          # 内嵌 UI 并安装 bsc
```

确认装到什么版本。版本号会带上构建时的 git commit，所以你随时分得出某台机器跑的是哪一版：

```sh
bsc --version        # bsc 0.1.0+f23d51a
```

### 3.2 创建保险库

```sh
bsc init
```

系统会要你输入口令两次，然后创建权限为 `0600` 的 `~/.bsc/vault.bsc`（设置 `BSC_HOME` 可换位置，或用 `--vault /path/to/vault.bsc` 指定）。

口令请取长一点。四、五个彼此无关的词，胜过一个拼写扭曲的短单词。密钥派生用 Argon2id，参数记录在文件里，所以暴力猜测会一直很慢；但任何出现在泄露密码字典里的口令，再怎么慢也救不回来。

**现在就备份保险库文件，之后每批改动也要备份。** 直接复制文件就够了，它本身就是加密的。文件和口令同时失去，内容就永久回不来。

### 3.3 启动，并让它持续启动

```sh
bsc service install     # 立即启动，并在每次登录时启动
bsc doctor              # ✅/⚠️/❌ 检查清单
```

`bsc service install` 会在 macOS 写一个 launchd agent、Linux 写一个 `systemd --user` unit、Windows 建一个登录时触发的任务计划程序，然后启动服务。加上 `--dry-run` 只打印定义与命令，不动系统任何东西。

想改用前台运行：

```sh
bsc serve               # Ctrl-C 结束
```

服务监听 `127.0.0.1:8787`，而且**启动时是上锁的**：在人类解封之前，它手上没有任何密钥。打开 <http://127.0.0.1:8787/>、输入口令，接下来请看[使用手册](guide.md)。

`bsc doctor` 会检查文件权限、审计链、服务是否有响应、UI 是否有内嵌、自动启动是否安装、系统时钟。觉得哪里不对就跑它；每一行不是 ✅，就是附理由的 ⚠️，或附解法的 ❌。

### 3.4 macOS 免输入口令解封（可选）

默认每次重启都要人来解封，这是安全的默认值。在自己的工作机上，你可以让服务从登录钥匙串自行解封：

```sh
security add-generic-password -s bsc-vault -a bsc -w   # 会提示输入口令
bsc service install --dry-run                          # 先看定义
```

然后在服务参数里加上 `--unseal-keychain bsc-vault`。从此只要能解锁你的登录钥匙串，就能解封保险库。常带出门的笔记本，还是自己输入口令比较好。

### 3.5 卸载

```sh
bsc service uninstall   # 停止服务、移除定义
rm ~/.local/bin/bsc     # 或当初安装的位置
```

保险库文件不会被动到。真的要销毁内容，请自己删掉 `~/.bsc/vault.bsc`——没有恢复机制。

---

## 4. 共享服务器（Linux、systemd、nginx）

服务本身不做 TLS，也不监听对外网卡。它待在 loopback，由前面的反向代理处理 TLS。[`deploy/`](../../../deploy) 里的配置文件就是生产环境正在跑的那份；这个架构保护得了什么、保护不了什么，写在 [`docs/DEPLOY_REVERSE_PROXY.md`](../../DEPLOY_REVERSE_PROXY.md)。

### 4.1 服务账号与保险库

```sh
sudo useradd --system --home /var/lib/bsc --shell /usr/sbin/nologin bsc
sudo install -d -m 0700 -o bsc -g bsc /var/lib/bsc
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo -u bsc bsc init --vault /var/lib/bsc/vault.bsc    # 口令自己输入
```

### 4.2 systemd unit

安装 [`deploy/bsc.service`](../../../deploy/bsc.service)，它以 `bsc` 用户运行，套用 `ProtectSystem=strict`，只有 `/var/lib/bsc` 可写：

```sh
sudo install -m 0644 deploy/bsc.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bsc
systemctl status bsc
```

把 unit 里的 `--bind` 与 `--public-origin` 改成你的端口与域名。`--public-origin https://secrets.example.com` 是在告诉服务「前面有一台 TLS 代理」：它会接受该 Origin、把 session cookie 标成 `Secure`、按转发来的客户端地址限流登录，并在审计链写下 `exposure_acknowledged`。没有这个参数，远程浏览器一律被拒。

### 4.3 nginx 与 TLS

从 [`deploy/nginx-sec.bastet.tw.conf`](../../../deploy/nginx-sec.bastet.tw.conf) 改起。真正重要的是这几点：

- 一张真证书，HTTP 跳转到 HTTPS；
- `proxy_pass http://127.0.0.1:8787;`，并用真正的客户端地址填 `X-Forwarded-For`（在 Cloudflare 后面就用 `CF-Connecting-IP`）；
- 对 `/v1/vault/unseal` 与 `/v1/items` 设 `limit_req`，让被盗的 session 没办法透过代理被暴力尝试。

然后从你自己的机器检查：

```sh
bsc doctor --url https://secrets.example.com
```

### 4.4 免人工解封（可选，服务器建议开启）

不开的话，每次重启保险库都会停在上锁状态，直到有人来输入口令。systemd 可以把口令存成加密凭据，只有该主机上的 root 解得开：

```sh
read -rsp "Vault passphrase: " PW && echo && \
  printf '%s' "$PW" | sudo systemd-creds encrypt --name=bsc-passphrase - /etc/bsc/passphrase.cred && \
  unset PW && sudo chmod 0600 /etc/bsc/passphrase.cred
```

接着把 [`deploy/bsc-unattended.conf`](../../../deploy/bsc-unattended.conf) 装成 drop-in，它会加上 `LoadCredentialEncrypted=` 与 `--unseal-credential bsc-passphrase`：

```sh
sudo install -d /etc/systemd/system/bsc.service.d
sudo install -m 0644 deploy/bsc-unattended.conf /etc/systemd/system/bsc.service.d/unattended.conf
sudo systemctl daemon-reload && sudo systemctl restart bsc
curl -s http://127.0.0.1:8787/v1/vault/status
```

应该看到 `"sealed":false,"unattended_unseal":"systemd-credential"`。请理解这个取舍：**该主机的 root 从此可以解封保险库。** 没有 TPM 的话，凭据绑在 `/var/lib/systemd/credential.secret`，而 root 读得到那个文件。若配置的解封来源失败，服务会直接退出，不会装作健康地停在上锁状态。

### 4.5 Telegram 审批通道（可选）

当 Agent 要读高价值敏感数据而你人不在机器前，服务可以发出一条带「批准／拒绝」按钮的消息。它只对外连接——不开任何 inbound 端口、不用 webhook——消息里不会有敏感数据内容，也不会有任何按下去就能取得敏感数据的链接。

在**服务器上**运行 [`deploy/telegram-setup.sh`](../../../deploy/telegram-setup.sh)；bot token 在那里输入，不会离开主机：

```sh
sudo ./telegram-setup.sh
```

脚本会用 `getMe` 验证 token、拒绝已设 webhook 的 bot、等你对 bot 发一条消息以取得 chat 与 user id、把 token 加密成 systemd 凭据、扩展 drop-in、重启并验证。标记为**仅限本机审批**的条目仍会通知，但不会有按钮：那种条目只能在 UI 审批。

### 4.6 每日审计链锚定（推荐）

审计链能检测被篡改的记录，但拥有文件的人理论上可以删掉末尾几条再重新串链。锚定就是补这个洞：每天把链长与链首记到保险库自己的用户改不动的地方。

```sh
sudo install -m 0644 deploy/bsc-anchor.service deploy/bsc-anchor.timer /etc/systemd/system/
sudo install -d -m 0700 /var/lib/bsc-anchors
sudo systemctl daemon-reload && sudo systemctl enable --now bsc-anchor.timer
systemctl list-timers bsc-anchor.timer
```

审计链一旦被截断或改写，这个 unit 会失败，`systemctl --failed` 就看得到。把你现有的主机监控接到那里即可。

### 4.7 升级

```sh
# 1. 在新可执行文件进入服务器之前先验证
shasum -a 256 -c bsc-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256

# 2. 备份保险库（服务运行中也能取得一致的副本）
sudo python3 -c "import sqlite3;s=sqlite3.connect('file:/var/lib/bsc/vault.bsc?mode=ro',uri=True);d=sqlite3.connect('/var/lib/bsc/vault.backup.bsc');s.backup(d)"

# 3. 安装并重启
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo systemctl restart bsc

# 4. 检查
curl -s http://127.0.0.1:8787/v1/vault/status     # 版本、是否上锁、解封方式
sudo bsc audit --vault /var/lib/bsc/vault.bsc     # 审计链完整
```

旧版创建的保险库，第一次被新版可执行文件打开时会在单一事务内自动迁移，迁移本身也写进审计链。若文件是**比可执行文件更新**的版本写的，程序会拒绝打开而不是把它弄坏。无论如何，还是先备份。

---

## 5. 故障排查

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| 浏览器只显示 `…`，什么都加载不出来 | 服务有响应，但某个请求失败了 | 看 `journalctl -u bsc -n 50` 或跑 `bsc serve` 的终端；最常见的是可执行文件与保险库版本不匹配 |
| Agent 收到 `vault_sealed` | 服务重启过 | 到 UI 解封。绝对不要把口令给 Agent |
| 远程浏览器被拒 | 没设 `--public-origin`，或值与网址不符 | 设成完全一致的 origin，含 `https://` |
| `bsc doctor` 说没有自动启动 | 没安装服务，或 bind 不同 | `bsc service install --bind …` |
| 试几次之后登录被挡 | 按客户端地址的登录限流 | 稍候再试；同时确认是不是有人在猜口令 |
| 日志出现 `no such column` | 可执行文件比保险库旧，或迁移失败 | 装上匹配的版本；必要时还原备份 |
| Telegram 按钮没反应 | chat 或 user id 不对，或该条目仅限本机审批 | 检查 unit 的 `--telegram-chat`／`--telegram-user`；改到 UI 审批 |

---

## 6. 让这套系统保持安全的规则

1. 口令由人输入，只输入到终端或 UI。永远不要进到对话、脚本、工单或仓库。
2. Agent 拿到的是 **token**，不是口令；token 也不要贴进提示词。它该待在配置文件里。
3. 服务待在 loopback。对外开放只能透过你刻意配置的反向代理。
4. 备份保险库文件，而且至少留一份在这台机器之外。
5. 保险库、导出文件、token、锚定文件，一律不得提交进仓库。这个 repo 只放源码与文档。
