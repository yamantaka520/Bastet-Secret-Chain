# 安裝手冊

**適用版本：**Bastet Secret Chain 0.2.0 · macOS、Windows、Linux
**語言：** **繁體中文** · [简体中文](../zh-Hans/install.md) · [English](../en/install.md) · [日本語](../ja/install.md) · [한국어](../ko/install.md)
**延伸閱讀：**[使用手冊](guide.md) · [Agent 接入手冊](agents.md)

整套系統只有一個檔案。`bsc` 這支執行檔同時是命令列工具、常駐服務、網頁伺服器，Web UI 也內嵌在裡面。不必安裝執行環境，不必架資料庫，不必用容器。保險庫是一個 SQLite 檔案，只有你解得開。

---

## 1. 開始之前

| 你需要 | 原因 |
| --- | --- |
| 一句你記得住、而且從沒在別處用過的密語 | 所有加密金鑰都由它推導。沒有人能替你重設——維護者不行、系統管理員不行、AI 助理也不行。 |
| 60 MB 磁碟空間 | 執行檔加保險庫。 |
| 一個終端機 | 安裝與第一次建立保險庫要用命令列。之後的操作都在 Web UI。 |

**密語絕對不要讓別人產生或看見，包括正在幫你安裝的 AI 助理。** 自己在自己的終端機或 Web UI 輸入。只要曾經出現在對話視窗裡，就當作已經外洩，立刻更換。

---

## 2. 選擇你的安裝型態

- **個人電腦**——保險庫跑在你的筆電上，只監聽 `127.0.0.1`，同一台機器上的 Agent 才用得到。請看第 3 節。
- **共用伺服器**——保險庫跑在 Linux 主機上，前面擺一台 TLS 反向代理，讓多個人與遠端 Agent 都能存取。請看第 4 節。伺服器上仍要先做完第 3 節，第 4 節取代其中的自動啟動與對外開放部分。

---

## 3. 個人電腦

### 3.1 安裝執行檔

**方式 A——安裝腳本（建議）。** 執行前請先讀過腳本；它不是設計來從網路直接管進 shell 的。

```sh
# macOS 與 Linux
curl -fsSLO https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.sh
less install.sh          # 先讀過
sh install.sh v0.2.0
```

```powershell
# Windows
Invoke-WebRequest -Uri https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.ps1 -OutFile install.ps1
notepad install.ps1      # 先讀過
.\install.ps1 -Version v0.2.0
```

腳本會下載對應平台的壓縮檔，比對同一份 release 發布的 `SHA256SUMS`，然後把 `bsc` 裝到 `~/.local/bin`（macOS、Linux）或 `%LOCALAPPDATA%\Programs\bsc`（Windows）。如果腳本提醒你，把該目錄加進 `PATH`。

這個比對能證明檔案在傳輸過程沒被損壞或掉包，但**不能**證明是誰建置的——因為雜湊值和檔案來自同一個發布頁。要驗證來源，再驗一次建置來源證明：

```sh
gh attestation verify bsc-0.2.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo yamantaka520/Bastet-Secret-Chain
```

從 v0.2.0 起，校驗和檔案也會用 Sigstore 無金鑰簽章：

```sh
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/yamantaka520/Bastet-Secret-Chain/.github/workflows/release.yml@refs/tags/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

這能證明檔案出自本專案版本庫的 release 工作流程、且來自某個 tag。它**不能**證明有維護者審核過那個 tag——這個專案沒有簽章金鑰，任何能推送 tag 的人都做得出有效簽章。[`SECURITY.md`](../../../SECURITY.md) 對此寫得很明白。

**方式 B——從原始碼建置。** 需要 Rust（stable）與 Node.js 22。

```sh
git clone https://github.com/yamantaka520/Bastet-Secret-Chain
cd Bastet-Secret-Chain
npm --prefix ui ci && npm --prefix ui run build   # 建置 Web UI
cargo install --path crates/bsc --locked          # 內嵌 UI 並安裝 bsc
```

確認裝到什麼版本。版號會帶上建置時的 git commit，所以你隨時分得出某台機器跑的是哪一版：

```sh
bsc --version        # bsc 0.2.0+9f3c1ab
```

### 3.2 建立保險庫

```sh
bsc init
```

系統會要你輸入密語兩次，然後建立權限為 `0600` 的 `~/.bsc/vault.bsc`（設定 `BSC_HOME` 可換位置，或用 `--vault /path/to/vault.bsc` 指定）。

密語請取長一點。四、五個彼此無關的詞，勝過一個扭曲拼寫的短字。金鑰推導用 Argon2id，參數記在檔案裡，所以暴力猜測會一直很慢；但任何出現在外洩密碼字典裡的密語，再怎麼慢也救不回來。

**現在就備份保險庫檔案，之後每批改動也要備份。** 直接複製檔案就夠了，它本身就是加密的。檔案和密語同時失去，內容就永久回不來。

### 3.3 啟動，並讓它持續啟動

```sh
bsc service install     # 立刻啟動，並在每次登入時啟動
bsc doctor              # ✅/⚠️/❌ 檢查清單
```

`bsc service install` 會在 macOS 寫一個 launchd agent、Linux 寫一個 `systemd --user` unit、Windows 建一個登入時觸發的工作排程，然後啟動服務。加上 `--dry-run` 只印出定義與指令，不動系統任何東西。

想改用前景執行：

```sh
bsc serve               # Ctrl-C 結束
```

服務監聽 `127.0.0.1:8787`，而且**啟動時是上鎖的**：在人類解封之前，它手上沒有任何金鑰。打開 <http://127.0.0.1:8787/>、輸入密語，接下來請看[使用手冊](guide.md)。

`bsc doctor` 會檢查檔案權限、稽核鏈、服務是否有回應、UI 是否有內嵌、自動啟動是否安裝、系統時鐘。覺得哪裡不對就跑它；每一行不是 ✅，就是附理由的 ⚠️，或附解法的 ❌。

### 3.4 macOS 免輸入密語解封（選用）

預設每次重啟都要人來解封，這是安全的預設值。在自己的工作機上，你可以讓服務從登入鑰匙圈自行解封：

```sh
security add-generic-password -s bsc-vault -a bsc -w   # 會提示輸入密語
bsc service install --dry-run                          # 先看定義
```

然後在服務參數加上 `--unseal-keychain bsc-vault`。從此只要能解鎖你的登入鑰匙圈，就能解封保險庫。常帶出門的筆電，還是自己輸入密語比較好。

### 3.5 移除

```sh
bsc service uninstall   # 停止服務、移除定義
rm ~/.local/bin/bsc     # 或當初安裝的位置
```

保險庫檔案不會被動到。真的要銷毀內容，請自己刪掉 `~/.bsc/vault.bsc`——沒有復原機制。

---

## 4. 共用伺服器（Linux、systemd、nginx）

服務本身不做 TLS，也不監聽對外介面。它待在 loopback，由前面的反向代理處理 TLS。[`deploy/`](../../../deploy) 裡的設定檔就是 production 正在跑的那份；這個架構保護得了什麼、保護不了什麼，寫在 [`docs/DEPLOY_REVERSE_PROXY.md`](../../DEPLOY_REVERSE_PROXY.md)。

### 4.1 服務帳號與保險庫

```sh
sudo useradd --system --home /var/lib/bsc --shell /usr/sbin/nologin bsc
sudo install -d -m 0700 -o bsc -g bsc /var/lib/bsc
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo -u bsc bsc init --vault /var/lib/bsc/vault.bsc    # 密語自己輸入
```

### 4.2 systemd unit

安裝 [`deploy/bsc.service`](../../../deploy/bsc.service)，它以 `bsc` 使用者執行，套用 `ProtectSystem=strict`，只有 `/var/lib/bsc` 可寫：

```sh
sudo install -m 0644 deploy/bsc.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bsc
systemctl status bsc
```

把 unit 裡的 `--bind` 與 `--public-origin` 改成你的埠號與網域。`--public-origin https://secrets.example.com` 是在告訴服務「前面有一台 TLS 代理」：它會接受該 Origin、把 session cookie 標成 `Secure`、依轉發來的用戶端位址節流登入，並在稽核鏈寫下 `exposure_acknowledged`。沒有這個參數，遠端瀏覽器一律被拒。

### 4.3 nginx 與 TLS

從 [`deploy/nginx-sec.bastet.tw.conf`](../../../deploy/nginx-sec.bastet.tw.conf) 改起。真正重要的是這幾點：

- 一張真憑證，HTTP 轉址到 HTTPS；
- `proxy_pass http://127.0.0.1:8787;`，並用真正的用戶端位址填 `X-Forwarded-For`（在 Cloudflare 後面就用 `CF-Connecting-IP`）；
- 對 `/v1/vault/unseal` 與 `/v1/items` 設 `limit_req`，讓被偷走的 session 沒辦法透過代理被暴力嘗試。

然後從你自己的機器檢查：

```sh
bsc doctor --url https://secrets.example.com
```

### 4.4 免人工解封（選用，伺服器建議開啟）

不開的話，每次重開機保險庫都會停在上鎖狀態，直到有人來輸入密語。systemd 可以把密語存成加密憑證，只有該主機上的 root 解得開：

```sh
read -rsp "Vault passphrase: " PW && echo && \
  printf '%s' "$PW" | sudo systemd-creds encrypt --name=bsc-passphrase - /etc/bsc/passphrase.cred && \
  unset PW && sudo chmod 0600 /etc/bsc/passphrase.cred
```

接著把 [`deploy/bsc-unattended.conf`](../../../deploy/bsc-unattended.conf) 裝成 drop-in，它會加上 `LoadCredentialEncrypted=` 與 `--unseal-credential bsc-passphrase`：

```sh
sudo install -d /etc/systemd/system/bsc.service.d
sudo install -m 0644 deploy/bsc-unattended.conf /etc/systemd/system/bsc.service.d/unattended.conf
sudo systemctl daemon-reload && sudo systemctl restart bsc
curl -s http://127.0.0.1:8787/v1/vault/status
```

應該看到 `"sealed":false,"unattended_unseal":"systemd-credential"`。請理解這個取捨：**該主機的 root 從此可以解封保險庫。** 沒有 TPM 的話，憑證綁在 `/var/lib/systemd/credential.secret`，而 root 讀得到那個檔案。若設定的解封來源失敗，服務會直接結束，不會裝作健康地停在上鎖狀態。

### 4.5 Telegram 核准通道（選用）

當 Agent 要讀高價值秘密而你人不在機器前，服務可以送出一則帶「核准／拒絕」按鈕的訊息。它只對外連線——不開任何 inbound 埠、不用 webhook——訊息裡不會有秘密內容，也不會有任何按下去就能取得秘密的連結。

在**伺服器上**執行 [`deploy/telegram-setup.sh`](../../../deploy/telegram-setup.sh)；bot token 在那裡輸入，不會離開主機：

```sh
sudo ./telegram-setup.sh
```

腳本會用 `getMe` 驗證 token、拒絕已設 webhook 的 bot、等你對 bot 發一則訊息以取得 chat 與 user id、把 token 加密成 systemd 憑證、擴充 drop-in、重啟並驗證。標記為**僅限本機核准**的項目仍會通知，但不會有按鈕：那種項目只能在 UI 核准。

### 4.6 每日稽核鏈錨定（建議）

稽核鏈能偵測被竄改的紀錄，但擁有檔案的人理論上可以砍掉尾端幾筆再重新串鏈。錨定就是補這個洞：每天把鏈長與鏈首記到保險庫自己的使用者改不動的地方。

```sh
sudo install -m 0644 deploy/bsc-anchor.service deploy/bsc-anchor.timer /etc/systemd/system/
sudo install -d -m 0700 /var/lib/bsc-anchors
sudo systemctl daemon-reload && sudo systemctl enable --now bsc-anchor.timer
systemctl list-timers bsc-anchor.timer
```

稽核鏈一旦被截尾或改寫，這個 unit 會失敗，`systemctl --failed` 就看得到。把你既有的主機監控接到那裡即可。

### 4.7 升級

```sh
# 1. 在新執行檔進到伺服器之前先驗證
shasum -a 256 -c bsc-0.2.0-x86_64-unknown-linux-gnu.tar.gz.sha256

# 2. 備份保險庫（服務執行中也能取得一致的副本）
sudo python3 -c "import sqlite3;s=sqlite3.connect('file:/var/lib/bsc/vault.bsc?mode=ro',uri=True);d=sqlite3.connect('/var/lib/bsc/vault.backup.bsc');s.backup(d)"

# 3. 安裝並重啟
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo systemctl restart bsc

# 4. 檢查
curl -s http://127.0.0.1:8787/v1/vault/status     # 版本、是否上鎖、解封方式
sudo bsc audit --vault /var/lib/bsc/vault.bsc     # 稽核鏈完整
```

舊版建立的保險庫，第一次被新版執行檔開啟時會在單一交易內自動遷移，遷移本身也寫進稽核鏈。若檔案是**比執行檔更新**的版本寫的，程式會拒絕開啟而不是弄壞它。無論如何，還是先備份。

---

## 5. 疑難排解

| 症狀 | 原因 | 處理 |
| --- | --- | --- |
| 瀏覽器只顯示 `…`，什麼都載入不出來 | 服務有回應，但某個請求失敗了 | 看 `journalctl -u bsc -n 50` 或跑 `bsc serve` 的終端機；最常見的是執行檔與保險庫版本不合 |
| Agent 收到 `vault_sealed` | 服務重啟過 | 到 UI 解封。絕對不要把密語給 Agent |
| 遠端瀏覽器被拒 | 沒設 `--public-origin`，或值與網址不符 | 設成完全一致的 origin，含 `https://` |
| `bsc doctor` 說沒有自動啟動 | 沒安裝服務，或 bind 不同 | `bsc service install --bind …` |
| 試幾次之後登入被擋 | 依用戶端位址的登入節流 | 稍候再試；同時確認是不是有人在猜密語 |
| 記錄檔出現 `no such column` | 執行檔比保險庫舊，或遷移失敗 | 裝上相符的版本；必要時還原備份 |
| Telegram 按鈕沒反應 | chat 或 user id 不對，或該項目僅限本機核准 | 檢查 unit 的 `--telegram-chat`／`--telegram-user`；改到 UI 核准 |

---

## 6. 讓這套系統保持安全的規則

1. 密語由人輸入，只輸入到終端機或 UI。永遠不要進到對話、腳本、工單或版本庫。
2. Agent 拿到的是 **token**，不是密語；token 也不要貼進提示詞。它該待在設定檔裡。
3. 服務待在 loopback。對外開放只能透過你刻意設定的反向代理。
4. 備份保險庫檔案，而且至少留一份在這台機器之外。
5. 保險庫、匯出檔、token、錨定檔，一律不得提交進版本庫。這個 repo 只放原始碼與文件。
