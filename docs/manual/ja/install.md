# インストールマニュアル

**対象:** Bastet Secret Chain 0.2.0 · macOS, Windows, Linux
**言語:** [繁體中文](../zh-Hant/install.md) · [简体中文](../zh-Hans/install.md) · [English](../en/install.md) · **日本語** · [한국어](../ko/install.md)
**関連:** [ユーザーガイド](guide.md) · [エージェントガイド](agents.md)

すべては 1 つのファイルに収まっています。`bsc` は単一のバイナリであり、コマンド
ライン、デーモン、Web サーバー、組み込みの Web UI のすべてを兼ねます。インストール
すべきランタイムも、データベースサーバーも、コンテナも必要ありません。保管庫は
あなただけが復号できる 1 つの SQLite ファイルです。

---

## 1. 始める前に

| 必要なもの | 理由 |
| --- | --- |
| 自分で記憶でき、他のどこでも使ったことのないパスフレーズ | すべてを暗号化する鍵を導出します。誰もリセットできません。メンテナーも、管理者も、AI アシスタントもです。 |
| 60 MB のディスク領域 | バイナリと保管庫の分です。 |
| ターミナル | インストールと最初の保管庫作成はコマンドラインで行います。それ以降はすべて Web UI です。 |

**パスフレーズを他人に生成させたり見せたりしては絶対にいけません。インストールを
手伝っている AI アシスタントも例外ではありません。** 自分自身のターミナル、または
Web UI に、自分の手で入力してください。チャットウィンドウに一度でも表示されたなら、
そのパスフレーズは漏洩したものとして扱い、変更してください。

---

## 2. 構成を選ぶ

- **個人のマシン** — 保管庫はあなたのノート PC 上で動作し、`127.0.0.1` からのみ
  到達できます。同じマシン上のエージェントがこれを利用します。セクション 3 へ
  進んでください。
- **共有サーバー** — 保管庫は TLS リバースプロキシの背後にある Linux ホスト上で
  動作し、複数の人とリモートのエージェントが到達できます。セクション 4 へ進んで
  ください。まずサーバー自身でセクション 3 を実施し、セクション 4 が自動起動と
  公開に関する部分を置き換えます。

---

## 3. 個人のマシン

### 3.1 バイナリのインストール

**選択肢 A — インストールスクリプト（推奨）。** 実行する前にスクリプトを読んで
ください。ネットワークからシェルへ直接パイプすることを意図したものではありません。

```sh
# macOS and Linux
curl -fsSLO https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.sh
less install.sh          # read it
sh install.sh v0.2.0
```

```powershell
# Windows
Invoke-WebRequest -Uri https://raw.githubusercontent.com/yamantaka520/Bastet-Secret-Chain/main/scripts/install.ps1 -OutFile install.ps1
notepad install.ps1      # read it
.\install.ps1 -Version v0.2.0
```

スクリプトはお使いのプラットフォーム向けのアーカイブをダウンロードし、同じ
リリースで公開されている `SHA256SUMS` と照合したうえで、`bsc` を `~/.local/bin`
（macOS、Linux）または `%LOCALAPPDATA%\Programs\bsc`（Windows）にインストール
します。スクリプトがそう指示した場合は、そのディレクトリを `PATH` に追加して
ください。

この照合は、アーカイブが転送中に破損したりすり替えられたりしていないことを証明
します。一方で、誰がビルドしたかは証明しません。チェックサムが同じリリースページ
から来ているためです。それを確認するには、ビルドの由来証明（provenance
attestation）も検証してください。

```sh
gh attestation verify bsc-0.2.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo yamantaka520/Bastet-Secret-Chain
```

v0.2.0 以降は、チェックサムファイルも Sigstore のキーレス署名で署名されます。

```sh
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/yamantaka520/Bastet-Secret-Chain/.github/workflows/release.yml@refs/tags/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

これは、ファイルがこのリポジトリのリリースワークフローからタグの時点で生成され
たことを証明します。一方で、メンテナーがそのタグを承認したことは証明しません。
このプロジェクトに署名鍵はなく、ここにタグをプッシュできる人なら誰でも有効な署
名を作れます。[`SECURITY.md`](../../../SECURITY.md) にもそのとおり明記されてい
ます。

**選択肢 B — ソースからビルドする。** Rust（stable）と Node.js 22 が必要です。

```sh
git clone https://github.com/yamantaka520/Bastet-Secret-Chain
cd Bastet-Secret-Chain
npm --prefix ui ci && npm --prefix ui run build   # builds the Web UI
cargo install --path crates/bsc --locked          # embeds it and installs bsc
```

何が入ったか確認します。バージョンにはビルド元の git コミットが含まれるため、
どのビルドがそのマシンで動いているかを常に判別できます。

```sh
bsc --version        # bsc 0.2.0+9f3c1ab
```

### 3.2 保管庫の作成

```sh
bsc init
```

パスフレーズを 2 回入力するよう求められます。これにより `0600` パーミッションの
`~/.bsc/vault.bsc` が作成されます（別の場所に置くには `BSC_HOME` を設定するか、
`--vault /path/to/vault.bsc` を渡します）。

長いパスフレーズを選んでください。関連のない 4〜5 個の単語のほうが、短くひねった
単語よりも優れています。鍵導出には Argon2id を使い、パラメータはファイルに記録
されるため、総当たりは遅いままです。ただし、パスワードリストに載っているパス
フレーズは何をもってしても救えません。

**保管庫ファイルは今すぐ、そして変更のたびにバックアップしてください。** ファイルを
コピーするだけで十分です。保存時点で暗号化されています。ファイルとパスフレーズの
両方を失うことは、中身を永久に失うことを意味します。

### 3.3 起動し、起動したままにする

```sh
bsc service install     # start now and at every login
bsc doctor              # ✅/⚠️/❌ checklist
```

`bsc service install` は、macOS では launchd エージェント、Linux では
`systemd --user` ユニット、Windows では Task Scheduler のログオンタスクを書き出し、
デーモンを起動します。`--dry-run` を付けると、何も変更せずに定義とコマンドを表示
します。

代わりにフォアグラウンドで実行するには次のようにします。

```sh
bsc serve               # Ctrl-C to stop
```

デーモンは `127.0.0.1:8787` で待ち受け、**施錠済みの状態で起動します**。人間が解封
するまで鍵を保持しません。<http://127.0.0.1:8787/> を開いてパスフレーズを入力し、
[ユーザーガイド](guide.md)へ進んでください。

`bsc doctor` は、ファイルパーミッション、台帳、デーモンが応答するか、UI が組み込
まれているか、自動起動が設定されているか、そして時刻を確認します。何かおかしいと
感じたら常に実行してください。各行は ✅、理由付きの ⚠️、または修正方法付きの ❌ の
いずれかです。

### 3.4 macOS での無人解封（任意）

デフォルトでは、再起動のたびに人間が解封します。これが安全なデフォルトです。
ワークステーションであれば、ログインキーチェーンからデーモン自身に解封させることも
できます。

```sh
security add-generic-password -s bsc-vault -a bsc -w   # prompts for the passphrase
bsc service install --dry-run                          # see the definition
```

続いて、サービスの引数に `--unseal-keychain bsc-vault` を追加します。これにより、
あなたのログインキーチェーンを解錠できる人は誰でも保管庫を解封できるようになります。
持ち歩くノート PC では、パスフレーズを入力する方式を選んでください。

### 3.5 アンインストール

```sh
bsc service uninstall   # stops the daemon, removes the definition
rm ~/.local/bin/bsc     # or wherever it was installed
```

保管庫ファイルはそのまま残ります。中身を破棄するつもりなら、`~/.bsc/vault.bsc` を
自分で削除してください。取り消しはできません。

---

## 4. 共有サーバー（Linux、systemd、nginx）

デーモンは TLS を終端せず、公開インターフェースで待ち受けることもありません。
ループバックにとどまり、その前段のリバースプロキシが TLS を担当します。
[`deploy/`](../../../deploy) にあるリファレンス設定は、本番で稼働しているものと
同じです。この構成が何を保護し、何を保護しないかについては
[`docs/DEPLOY_REVERSE_PROXY.md`](../../DEPLOY_REVERSE_PROXY.md) を読んでください。

### 4.1 サービスアカウントと保管庫

```sh
sudo useradd --system --home /var/lib/bsc --shell /usr/sbin/nologin bsc
sudo install -d -m 0700 -o bsc -g bsc /var/lib/bsc
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo -u bsc bsc init --vault /var/lib/bsc/vault.bsc    # type the passphrase yourself
```

### 4.2 systemd ユニット

[`deploy/bsc.service`](../../../deploy/bsc.service) をインストールします。これは
`bsc` ユーザーとして `ProtectSystem=strict` で動作し、書き込み可能なのは
`/var/lib/bsc` だけです。

```sh
sudo install -m 0644 deploy/bsc.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bsc
systemctl status bsc
```

ユニット内の `--bind` と `--public-origin` を、自分のポートとホスト名に合わせて
調整してください。`--public-origin https://secrets.example.com` は、TLS プロキシが
前段にあることをデーモンに伝えます。その Origin を受け入れ、セッション Cookie に
`Secure` を付け、転送元クライアントアドレスごとにログインを絞り、
`exposure_acknowledged` を台帳に書き込みます。これがないと、リモートのブラウザは
拒否されます。

### 4.3 nginx と TLS

[`deploy/nginx-bsc.conf`](../../../deploy/nginx-bsc.conf) を
出発点にしてください。重要な点は次のとおりです。

- 本物の証明書と、HTTP から HTTPS へのリダイレクト。
- `proxy_pass http://127.0.0.1:8787;` と、実際のクライアントアドレスから設定した
  `X-Forwarded-For`（Cloudflare の背後では `CF-Connecting-IP` から）。
- `/v1/vault/unseal` と `/v1/items` に対する `limit_req`。盗まれたセッションが
  プロキシ越しに総当たりされないようにするためです。

その後、自分のマシンから確認します。

```sh
bsc doctor --url https://secrets.example.com
```

### 4.4 人手を介さない解封（任意、サーバーでは推奨）

これがないと、再起動のたびに誰かがパスフレーズを入力するまで保管庫は施錠された
ままになります。systemd は、そのホスト上の root だけが復号できる暗号化された
クレデンシャルとしてパスフレーズを保持できます。

```sh
read -rsp "Vault passphrase: " PW && echo && \
  printf '%s' "$PW" | sudo systemd-creds encrypt --name=bsc-passphrase - /etc/bsc/passphrase.cred && \
  unset PW && sudo chmod 0600 /etc/bsc/passphrase.cred
```

続いて、[`deploy/bsc-unattended.conf`](../../../deploy/bsc-unattended.conf) を
drop-in としてインストールします。これは `LoadCredentialEncrypted=` と
`--unseal-credential bsc-passphrase` を追加します。

```sh
sudo install -d /etc/systemd/system/bsc.service.d
sudo install -m 0644 deploy/bsc-unattended.conf /etc/systemd/system/bsc.service.d/unattended.conf
sudo systemctl daemon-reload && sudo systemctl restart bsc
curl -s http://127.0.0.1:8787/v1/vault/status
```

`"sealed":false,"unattended_unseal":"systemd-credential"` が返るはずです。
このトレードオフを理解してください。**そのホストの root は、これで保管庫を解封
できるようになります。** TPM がない場合、クレデンシャルは
`/var/lib/systemd/credential.secret` に紐づけられ、これは root が読み取れます。
設定された解封ソースが失敗した場合、デーモンは施錠済みのまま起動して正常を装う
のではなく、終了します。

### 4.5 Telegram 承認チャネル（任意）

エージェントが価値の高いシークレットを要求したときに誰もマシンの前にいない場合、
デーモンは Approve / Deny ボタン付きのメッセージを 1 通送信できます。これは送信
専用で、着信ポートも Webhook もありません。またメッセージには、シークレットも、
それを取り出せるリンクも一切含まれません。

[`deploy/telegram-setup.sh`](../../../deploy/telegram-setup.sh) を**サーバー上で**
実行してください。ボットトークンはそこで入力され、そこから出ることはありません。

```sh
sudo ./telegram-setup.sh
```

このスクリプトは `getMe` でトークンを検証し、Webhook を持つボットを拒否し、
チャットとユーザー ID を学習できるようあなたがボットにメッセージを送るのを待ち、
トークンを systemd クレデンシャルとして暗号化し、drop-in を拡張し、再起動して検証
します。*ローカル承認のみ* と設定されたアイテムは通知はされますがボタンは付きま
せん。UI でのみ承認できます。

### 4.6 台帳の日次アンカー（推奨）

監査チェーンは改変を検知しますが、チェーンの所有者は原理的には末尾のレコードを
削除して再リンクできてしまいます。アンカーはその穴を塞ぎます。日次ジョブが、
チェーンの長さと先頭を、保管庫のユーザー自身では書き換えられない場所に記録します。

```sh
sudo install -m 0644 deploy/bsc-anchor.service deploy/bsc-anchor.timer /etc/systemd/system/
sudo install -d -m 0700 /var/lib/bsc-anchors
sudo systemctl daemon-reload && sudo systemctl enable --now bsc-anchor.timer
systemctl list-timers bsc-anchor.timer
```

台帳が切り詰められたり書き換えられたりすると、このユニットは失敗し、
`systemctl --failed` に表示されます。すでにホストを監視している仕組みがあれば、
それを見張らせてください。

### 4.7 アップグレード

```sh
# 1. verify the new binary before it reaches the server
shasum -a 256 -c bsc-0.2.0-x86_64-unknown-linux-gnu.tar.gz.sha256

# 2. back up the vault (a consistent copy, while the daemon runs)
sudo python3 -c "import sqlite3;s=sqlite3.connect('file:/var/lib/bsc/vault.bsc?mode=ro',uri=True);d=sqlite3.connect('/var/lib/bsc/vault.backup.bsc');s.backup(d)"

# 3. install and restart
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo systemctl restart bsc

# 4. check
curl -s http://127.0.0.1:8787/v1/vault/status     # version, sealed, unattended_unseal
sudo bsc audit --vault /var/lib/bsc/vault.bsc     # ledger intact
```

古いバージョンで作成された保管庫は、新しいバイナリが初めて開いたときに 1 つの
トランザクションで自動的に移行され、その移行は台帳に記録されます。バイナリより
*新しい*バージョンで書かれたファイルは、破損させるのではなく拒否されます。それでも
先にバックアップを取ってください。

---

## 5. トラブルシューティング

| 症状 | 原因 | 対処 |
| --- | --- | --- |
| ブラウザに `…` だけが表示され何も読み込まれない | デーモンは応答しているが、あるリクエストが失敗している | `journalctl -u bsc -n 50`、または `bsc serve` を実行しているターミナルを確認。よくある原因はバイナリと保管庫のバージョン不一致 |
| エージェントに `vault_sealed` が返る | デーモンが再起動した | UI で解封する。パスフレーズをエージェントに渡してはいけない |
| リモートのブラウザが拒否される | `--public-origin` がない、または URL と一致しない | `https://` を含む正確な Origin を設定する |
| `bsc doctor` が自動起動なしと表示する | サービスが未インストール、または別の bind になっている | `bsc service install --bind …` |
| 数回試したあとログインが拒否される | クライアントアドレスごとのログイン制限 | 待ってから再試行する。誰かが推測を試みていないか確認する |
| ログに `no such column` が出る | バイナリが保管庫より古い、または移行に失敗した | 対応するバイナリをインストールする。必要ならバックアップから復元する |
| Telegram のボタンが反応しない | チャットが違う、ユーザー ID が違う、またはアイテムが local-only になっている | ユニットの `--telegram-chat` / `--telegram-user` を確認する。UI で承認する |

---

## 6. 安全を保つためのルール

1. パスフレーズは人間が、ターミナルまたは UI に入力します。チャット、スクリプト、
   チケット、リポジトリには絶対に入力しません。
2. エージェントに渡すのは**トークン**であり、パスフレーズは決して渡しません。また
   トークンをプロンプトに貼り付けることも決してしません。トークンは設定ファイルに
   置くものです。
3. デーモンはループバックにとどまります。外部への公開は、自分が意図して設定した
   プロキシを通じて行われます。
4. 保管庫ファイルをバックアップし、少なくとも 1 つはそのマシンの外に保管します。
5. 保管庫、エクスポート、トークン、アンカーファイルを決してコミットしません。
   リポジトリにあるのはソースとドキュメントだけです。
