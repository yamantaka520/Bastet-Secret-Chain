# 설치 매뉴얼

**적용 대상:** Bastet Secret Chain 0.2.0 · macOS, Windows, Linux
**언어:** [繁體中文](../zh-Hant/install.md) · [简体中文](../zh-Hans/install.md) · [English](../en/install.md) · [日本語](../ja/install.md) · **한국어**
**함께 보기:** [사용자 가이드](guide.md) · [에이전트 가이드](agents.md)

모든 것이 파일 하나입니다. `bsc`는 명령줄, 데몬, 웹 서버, 내장 Web UI를 한꺼번에
담은 단일 바이너리입니다. 설치할 런타임도, 데이터베이스 서버도, 컨테이너도
필요하지 않습니다. 보관소(볼트)는 오직 사용자만 복호화할 수 있는 SQLite 파일
하나입니다.

---

## 1. 시작하기 전에

| 필요한 것 | 이유 |
| --- | --- |
| 기억할 수 있고 다른 곳에 한 번도 쓴 적 없는 패스프레이즈 | 모든 것을 암호화하는 키를 여기서 파생합니다. 아무도 재설정할 수 없습니다 — 메인테이너도, 관리자도, AI 어시스턴트도 마찬가지입니다. |
| 디스크 60 MB | 바이너리와 보관소(볼트)를 합친 용량입니다. |
| 터미널 | 설치와 최초 보관소(볼트) 생성은 명령줄 작업입니다. 그 이후는 모두 Web UI에서 진행합니다. |

**설치를 도와주는 AI 어시스턴트를 포함해, 다른 누구에게도 패스프레이즈를
생성하게 하거나 보여주지 마십시오.** 직접 본인의 터미널이나 Web UI에 입력하십시오.
채팅 창에 한 번이라도 들어간 적이 있다면 이미 노출된 것으로 간주하고 즉시
변경하십시오.

---

## 2. 구성 방식 선택

- **개인 머신** — 보관소(볼트)가 노트북에서 실행되며 `127.0.0.1`에서만 접근할 수
  있습니다. 같은 머신의 에이전트가 이를 사용합니다. 3절로 이동하십시오.
- **공유 서버** — 보관소(볼트)가 TLS 리버스 프록시 뒤의 Linux 호스트에서 실행되어
  여러 사람과 원격 에이전트가 접근할 수 있습니다. 4절로 이동하십시오.
  서버에서 먼저 3절을 수행하고, 4절이 자동 시작과 외부 노출 부분을 대체합니다.

---

## 3. 개인 머신

### 3.1 바이너리 설치

**옵션 A — 설치 스크립트(권장).** 실행하기 전에 스크립트를 읽어보십시오. 네트워크에서
셸로 곧바로 파이프하도록 만든 것이 아닙니다.

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

스크립트는 사용 중인 플랫폼용 아카이브를 내려받고, 같은 릴리스에 함께 공개된
`SHA256SUMS`와 대조한 뒤, `bsc`를 `~/.local/bin`(macOS, Linux) 또는
`%LOCALAPPDATA%\Programs\bsc`(Windows)에 설치합니다. 스크립트가 안내하면 해당
디렉터리를 `PATH`에 추가하십시오.

이 검사는 아카이브가 전송 중 손상되거나 바꿔치기되지 않았음을 증명합니다. 합계
값이 같은 릴리스 페이지에서 오기 때문에 누가 빌드했는지까지 증명하지는 않습니다.
그것까지 확인하려면 빌드 프로비넌스 어테스테이션도 함께 검증하십시오.

```sh
gh attestation verify bsc-0.2.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo yamantaka520/Bastet-Secret-Chain
```

v0.2.0부터는 체크섬 파일도 Sigstore 키리스 서명으로 서명됩니다.

```sh
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/yamantaka520/Bastet-Secret-Chain/.github/workflows/release.yml@refs/tags/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

이는 해당 파일이 이 저장소의 릴리스 워크플로에서 태그 시점에 만들어졌음을
증명합니다. 그러나 메인테이너가 그 태그를 승인했다는 것은 증명하지 않습니다.
이 프로젝트에는 서명 키가 없으며, 여기에 태그를 푸시할 수 있는 사람이라면
누구나 유효한 서명을 만들 수 있습니다. [`SECURITY.md`](../../../SECURITY.md)에
이 점이 분명히 기술되어 있습니다.

**옵션 B — 소스에서 빌드.** Rust(stable)와 Node.js 22가 필요합니다.

```sh
git clone https://github.com/yamantaka520/Bastet-Secret-Chain
cd Bastet-Secret-Chain
npm --prefix ui ci && npm --prefix ui run build   # builds the Web UI
cargo install --path crates/bsc --locked          # embeds it and installs bsc
```

설치된 결과를 확인하십시오. 버전에는 빌드에 사용된 git 커밋이 함께 들어 있어,
어떤 머신이 어떤 빌드를 실행 중인지 언제나 알 수 있습니다.

```sh
bsc --version        # bsc 0.2.0+9f3c1ab
```

### 3.2 보관소(볼트) 생성

```sh
bsc init
```

패스프레이즈를 두 번 입력하라는 안내가 나옵니다. 이 명령은 `0600` 권한으로
`~/.bsc/vault.bsc`를 생성합니다(다른 위치에 두려면 `BSC_HOME`을 설정하거나
`--vault /path/to/vault.bsc`를 전달하십시오).

긴 패스프레이즈를 선택하십시오. 서로 관련 없는 단어 네다섯 개가 짧게 변형한 단어
하나보다 낫습니다. 키 파생은 파일에 파라미터가 기록되는 Argon2id를 사용하므로
느린 추측은 계속 느리게 유지되지만, 패스워드 목록에 등장하는 패스프레이즈는 그
무엇으로도 구제할 수 없습니다.

**지금, 그리고 변경 작업을 한 묶음씩 마칠 때마다 보관소(볼트) 파일을
백업하십시오.** 파일을 복사하는 것만으로 충분합니다. 저장 상태에서 암호화되어
있습니다. 파일과 패스프레이즈를 모두 잃으면 내용도 영구히 사라집니다.

### 3.3 시작하고, 계속 실행되게 하기

```sh
bsc service install     # start now and at every login
bsc doctor              # ✅/⚠️/❌ checklist
```

`bsc service install`은 macOS에서는 launchd 에이전트를, Linux에서는
`systemd --user` 유닛을, Windows에서는 작업 스케줄러 로그온 작업을 작성한 뒤
데몬을 시작합니다. `--dry-run`을 추가하면 아무것도 건드리지 않고 정의와 명령만
출력합니다.

대신 포그라운드로 실행하려면 다음과 같이 하십시오.

```sh
bsc serve               # Ctrl-C to stop
```

데몬은 `127.0.0.1:8787`에서 수신하며 **잠긴 상태로 시작합니다**. 사람이 봉인을
해제하기 전까지는 어떤 키도 보유하지 않습니다. <http://127.0.0.1:8787/>을 열고
패스프레이즈를 입력한 뒤 [사용자 가이드](guide.md)로 이어가십시오.

`bsc doctor`는 파일 권한, 원장, 데몬 응답 여부, UI 내장 여부, 자동 시작 설치 여부,
그리고 시계를 점검합니다. 무언가 이상하다고 느껴질 때마다 실행하십시오. 모든 줄은
✅이거나, 이유가 붙은 ⚠️, 또는 해결 방법이 붙은 ❌ 중 하나입니다.

### 3.4 macOS에서 무인 봉인 해제(선택)

기본값은 재시작할 때마다 사람이 봉인을 해제하는 것입니다. 그것이 안전한
기본값입니다. 워크스테이션에서는 데몬이 로그인 키체인에서 스스로 봉인을 해제하도록
할 수 있습니다.

```sh
security add-generic-password -s bsc-vault -a bsc -w   # prompts for the passphrase
bsc service install --dry-run                          # see the definition
```

그런 다음 서비스의 인수에 `--unseal-keychain bsc-vault`를 추가하십시오. 이렇게 하면
로그인 키체인을 잠금 해제할 수 있는 사람은 누구나 보관소(볼트)의 봉인을 해제할 수
있습니다. 들고 다니는 노트북에서는 패스프레이즈를 직접 입력하는 편이 낫습니다.

### 3.5 제거

```sh
bsc service uninstall   # stops the daemon, removes the definition
rm ~/.local/bin/bsc     # or wherever it was installed
```

보관소(볼트) 파일은 그대로 남습니다. 내용을 파기할 생각이라면 `~/.bsc/vault.bsc`를
직접 삭제하십시오. 되돌릴 방법은 없습니다.

---

## 4. 공유 서버 (Linux, systemd, nginx)

데몬은 TLS를 종단하지 않으며 공개 인터페이스에서 수신하지도 않습니다. 데몬은
루프백에 머무르고, 그 앞의 리버스 프록시가 TLS를 담당합니다.
[`deploy/`](../../../deploy)에 있는 참조 구성은 실제 프로덕션에서 사용 중인
것입니다. 그 구성이 무엇을 보호하고 무엇을 보호하지 않는지는
[`docs/DEPLOY_REVERSE_PROXY.md`](../../DEPLOY_REVERSE_PROXY.md)를 읽어보십시오.

### 4.1 서비스 계정과 보관소(볼트)

```sh
sudo useradd --system --home /var/lib/bsc --shell /usr/sbin/nologin bsc
sudo install -d -m 0700 -o bsc -g bsc /var/lib/bsc
sudo install -m 0755 ./bsc /usr/local/bin/bsc
sudo -u bsc bsc init --vault /var/lib/bsc/vault.bsc    # type the passphrase yourself
```

### 4.2 systemd 유닛

`ProtectSystem=strict`와 함께 `bsc` 사용자로 실행되고 `/var/lib/bsc`만 쓰기 가능한
[`deploy/bsc.service`](../../../deploy/bsc.service)를 설치하십시오.

```sh
sudo install -m 0644 deploy/bsc.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bsc
systemctl status bsc
```

유닛의 `--bind`와 `--public-origin`을 사용 중인 포트와 호스트명에 맞게
조정하십시오. `--public-origin https://secrets.example.com`은 TLS 프록시가 앞에
있음을 데몬에 알립니다. 그러면 데몬은 해당 Origin을 수용하고, 세션 쿠키에 `Secure`를
표시하며, 전달된 클라이언트 주소별로 로그인을 스로틀링하고, 원장에
`exposure_acknowledged`를 기록합니다. 이 옵션이 없으면 원격 브라우저는 거부됩니다.

### 4.3 nginx와 TLS

[`deploy/nginx-sec.bastet.tw.conf`](../../../deploy/nginx-sec.bastet.tw.conf)에서
시작하십시오. 중요한 부분은 다음과 같습니다.

- 실제 인증서, 그리고 HTTP에서 HTTPS로의 리다이렉트;
- 실제 클라이언트 주소에서 설정한 `X-Forwarded-For`와 함께 사용하는
  `proxy_pass http://127.0.0.1:8787;`(Cloudflare 뒤에서는 `CF-Connecting-IP`에서);
- 탈취된 세션이 프록시를 통해 무차별 대입 공격을 당하지 않도록
  `/v1/vault/unseal`과 `/v1/items`에 적용하는 `limit_req`.

그런 다음 본인의 머신에서 확인하십시오.

```sh
bsc doctor --url https://secrets.example.com
```

### 4.4 사람 없이 봉인 해제(선택, 서버에 권장)

그렇게 하지 않으면 재부팅할 때마다 누군가 패스프레이즈를 입력할 때까지 보관소(볼트)가
잠긴 상태로 남습니다. systemd는 해당 호스트에서 root만 복호화할 수 있는 암호화된
크리덴셜로 이를 보관할 수 있습니다.

```sh
read -rsp "Vault passphrase: " PW && echo && \
  printf '%s' "$PW" | sudo systemd-creds encrypt --name=bsc-passphrase - /etc/bsc/passphrase.cred && \
  unset PW && sudo chmod 0600 /etc/bsc/passphrase.cred
```

그런 다음 `LoadCredentialEncrypted=`와 `--unseal-credential bsc-passphrase`를
추가하는 [`deploy/bsc-unattended.conf`](../../../deploy/bsc-unattended.conf)를
드롭인으로 설치하십시오.

```sh
sudo install -d /etc/systemd/system/bsc.service.d
sudo install -m 0644 deploy/bsc-unattended.conf /etc/systemd/system/bsc.service.d/unattended.conf
sudo systemctl daemon-reload && sudo systemctl restart bsc
curl -s http://127.0.0.1:8787/v1/vault/status
```

`"sealed":false,"unattended_unseal":"systemd-credential"`이 나와야 합니다. 이때의
맞바꿈을 이해하십시오. **이제 그 호스트의 root는 보관소(볼트)의 봉인을 해제할 수
있습니다.** TPM이 없으면 크리덴셜은 root가 읽을 수 있는
`/var/lib/systemd/credential.secret`에 묶입니다. 구성된 봉인 해제 소스가 실패하면,
데몬은 잠긴 상태로 시작해 정상인 척하는 대신 종료합니다.

### 4.5 Telegram 승인 채널(선택)

에이전트가 가치가 높은 시크릿을 요청했는데 머신 앞에 아무도 없을 때, 데몬은 Approve /
Deny 버튼이 달린 메시지를 하나 보낼 수 있습니다. 아웃바운드 전용이며 — 인바운드
포트도, 웹훅도 없습니다 — 메시지에는 시크릿도, 시크릿을 넘겨줄 링크도 절대 포함되지
않습니다.

[`deploy/telegram-setup.sh`](../../../deploy/telegram-setup.sh)를 **서버에서**
실행하십시오. 봇 토큰은 그곳에서 입력되며 서버를 벗어나지 않습니다.

```sh
sudo ./telegram-setup.sh
```

스크립트는 `getMe`로 토큰을 검증하고, 웹훅이 설정된 봇은 거부하며, 채팅 id와 사용자
id를 알아낼 수 있도록 사용자가 봇에게 메시지를 보낼 때까지 기다린 뒤, 토큰을 systemd
크리덴셜로 암호화하고, 드롭인을 확장하고, 재시작하여 검증합니다. *로컬 승인 전용*으로
표시된 항목은 여전히 알림은 보내지만 버튼은 제공되지 않습니다. 이런 항목은 UI에서만
승인할 수 있습니다.

### 4.6 일일 원장 앵커(권장)

감사 체인은 편집을 탐지하지만, 체인 소유자는 원리상 끝부분의 레코드를 잘라내고 다시
연결할 수 있습니다. 앵커가 그 틈을 막습니다. 매일 실행되는 작업이 체인 길이와 헤드를
보관소(볼트)의 소유자 본인이 다시 쓸 수 없는 곳에 기록합니다.

```sh
sudo install -m 0644 deploy/bsc-anchor.service deploy/bsc-anchor.timer /etc/systemd/system/
sudo install -d -m 0700 /var/lib/bsc-anchors
sudo systemctl daemon-reload && sudo systemctl enable --now bsc-anchor.timer
systemctl list-timers bsc-anchor.timer
```

원장이 잘리거나 다시 쓰이면 유닛이 실패하고 `systemctl --failed`에 표시됩니다. 이미
호스트를 감시하고 있는 도구가 있다면 그것이 이 신호를 보게 하십시오.

### 4.7 업그레이드

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

이전 버전으로 만든 보관소(볼트)는 더 새로운 바이너리가 처음 열 때 하나의 트랜잭션
안에서 자동으로 마이그레이션되며, 마이그레이션 사실이 원장에 기록됩니다. 바이너리보다
*더 새로운* 버전이 기록한 파일은 손상시키는 대신 거부합니다. 그래도 먼저
백업하십시오.

---

## 5. 문제 해결

| 증상 | 원인 | 해결 |
| --- | --- | --- |
| 브라우저에 `…`만 표시되고 아무것도 로드되지 않음 | 데몬은 응답하고 있으나 어떤 요청이 실패하는 중 | `journalctl -u bsc -n 50` 또는 `bsc serve`를 실행 중인 터미널을 확인하십시오. 대개는 바이너리와 보관소(볼트) 사이의 버전 불일치가 원인입니다 |
| 에이전트에서 `vault_sealed` 발생 | 데몬이 재시작됨 | UI에서 봉인을 해제하십시오. 절대 에이전트에게 패스프레이즈를 주지 마십시오 |
| 원격 브라우저가 거부됨 | `--public-origin`이 없거나 URL과 일치하지 않음 | `https://`를 포함해 정확한 오리진으로 설정하십시오 |
| `bsc doctor`가 자동 시작이 없다고 표시 | 서비스가 설치된 적이 없거나 바인드가 다름 | `bsc service install --bind …` |
| 몇 번 시도한 뒤 로그인이 거부됨 | 클라이언트 주소별 로그인 스로틀링 | 기다렸다가 다시 시도하십시오. 다른 누군가가 추측을 시도하고 있는지 확인하십시오 |
| 로그에 `no such column` | 바이너리가 보관소(볼트)보다 오래되었거나 마이그레이션이 실패함 | 맞는 바이너리를 설치하고, 필요하면 백업을 복원하십시오 |
| Telegram 버튼이 동작하지 않음 | 잘못된 채팅, 잘못된 사용자 id, 또는 로컬 전용으로 표시된 항목 | 유닛의 `--telegram-chat` / `--telegram-user`를 확인하고, UI에서 승인하십시오 |

---

## 6. 안전을 지키는 규칙

1. 패스프레이즈는 사람이 터미널이나 UI에 직접 입력합니다. 채팅, 스크립트, 티켓,
   저장소에는 절대 입력하지 마십시오.
2. 에이전트에게는 **토큰**만 주고, 패스프레이즈는 절대 주지 마십시오. 토큰도
   프롬프트에 붙여 넣어서는 안 됩니다. 토큰이 있어야 할 곳은 설정 파일입니다.
3. 데몬은 루프백에 머무릅니다. 외부 노출은 의도적으로 구성한 프록시를 통해서만
   이루어집니다.
4. 보관소(볼트) 파일을 백업하고, 최소한 한 부는 해당 머신 밖에 보관하십시오.
5. 보관소(볼트), 내보내기 파일, 토큰, 앵커 파일은 절대 커밋하지 마십시오. 저장소에는
   소스와 문서만 둡니다.
