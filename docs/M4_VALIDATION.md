# M4 Validation — packaging and auto-start

**Milestone:** M4 from [`MASTER_PLAN.md`](MASTER_PLAN.md) §6.
**Gate text:** macOS/Windows/Linux artifacts, `service install`, `doctor`;
three-platform CI plus one real-machine reboot survival test per platform.
**Status:** partially met, 2026-09-04 — artifacts, `service install`, and
`doctor` are delivered and CI-verified on three platforms; the LaunchAgent was
installed, killed, watched come back, and removed on a real Mac; the **reboot
itself was not performed on any platform** (see the last section). Nothing
here is a release.

## What was built

| Piece | Purpose |
| --- | --- |
| `bsc service install / uninstall / status` | Boot auto-start through the platform's own supervisor, at user level, no elevation: a launchd LaunchAgent (`~/Library/LaunchAgents/io.bastet.bsc.plist`, `RunAtLoad` + `KeepAlive`), a systemd **user** unit (`~/.config/systemd/user/bsc.service`, `Restart=on-failure`, `WantedBy=default.target`, `NoNewPrivileges`, `UMask=0077`, `ReadWritePaths=<vault dir>`), or a Task Scheduler logon task (`schtasks /SC ONLOGON /RL LIMITED`). `--dry-run` prints the definition and the exact commands and touches nothing. |
| `bsc doctor` | ✅/⚠️/❌ checklist: vault present, `0600` file and `0700` directory, header and Argon2id parameters, audit chain intact, directory writable, URL is loopback, daemon reachable (version, sealed), UI served with CSP, auto-start installed (plus `loginctl enable-linger` advice on Linux), notification tool present, clock sane. Exit is non-zero only for ❌. |
| CI `artifacts` job | Release build of `bsc` for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` with the UI embedded, packaged as `tar.gz`/`zip` with a `.sha256`, smoke-tested (`--version`, `init --passphrase-stdin`, `audit`) from the *unpacked archive*, uploaded as workflow artifacts on every push to `main`. |
| `release.yml` | Dormant until a `v*` tag: the same builds plus `x86_64-apple-darwin`, `SHA256SUMS`, GitHub build-provenance attestations, a **draft** GitHub Release. |
| `scripts/install.sh`, `scripts/install.ps1` | Download a named version, verify against the release's `SHA256SUMS`, install to `~/.local/bin` / `%LOCALAPPDATA%\Programs\bsc`. They state plainly that this is integrity, not authenticity, and ask not to be piped from the network into a shell. |
| CI definition checks | macOS: `plutil -lint` on the generated plist. Linux: `systemd-analyze verify` on the generated unit. Both platforms: `doctor` on a fresh vault. |

Design notes:

- Definitions are pure functions of `(os, exe, vault, bind, home)`, so every
  platform's plist/unit/schtasks line is unit-tested on every platform, not
  just the host's.
- `install` refuses without an existing vault and points at `bsc init`.
  `uninstall` never touches the vault file.
- The macOS install sequence is `bootout` (tolerated failure) → `bootstrap` →
  `kickstart -k`, so re-installing picks up a changed definition.
- Windows uses a logon task rather than an SCM service because a service
  needs elevation and a wrapper; the task runs as the user with `LIMITED`
  rights. An SCM option is a later decision.
- The systemd unit deliberately omits `ProtectSystem`/`ProtectHome`: user
  units with those options fail on some hosts without user namespaces. Noted
  as hardening for M7.

## Evidence — local, macOS, 2026-09-04

```
cargo fmt --all -- --check                                    ok
cargo clippy --workspace --all-targets -- -D warnings          ok (0 warnings)
cargo test --workspace                                         95 passed, 0 failed
  new in M4: bsc service unit tests 7 · bsc tests/service_doctor 6
bsc service install --dry-run --vault …/demo.bsc               prints plist + launchctl commands, writes nothing
plutil -lint <extracted plist>                                 OK
bsc doctor --vault …/demo.bsc --url http://127.0.0.1:8797      ✅ vault · ✅ permissions 0600 · ✅ directory 0700 ·
                                                               ✅ format Argon2id 64 MiB · ✅ audit chain intact (25) ·
                                                               ✅ writable · ✅ bind loopback · ⚠️ daemon not reachable ·
                                                               ⚠️ auto-start not installed · ✅ osascript · ✅ clock
bsc --version                                                  bsc 0.0.0
```

### What the tests establish

Unit: the plist carries every argument and is balanced; XML is escaped in
paths; the unit has `Restart=on-failure`, `WantedBy=default.target`,
hardening lines, and quotes paths with spaces; Windows uses `ONLOGON` with
`/RL LIMITED` and no definition file; definition paths are per-user; the
macOS command order is bootout → bootstrap → kickstart.

Binary: `service install --dry-run` prints the platform's definition and
commands and writes **nothing** under a fake `$HOME`; `install` refuses
without a vault; `doctor` fails on a missing vault, warns (exit 0) on a stopped
daemon, fails on a broken ledger and on a non-loopback URL, sees a running
daemon and its UI, and never blocks on stdin.

## Live test on a real Mac — 2026-09-04, with the operator's go-ahead

Performed with the debug binary and the disposable demo vault, then removed:

```
bsc service install --vault …/demo.bsc --bind 127.0.0.1:8797
  write ~/Library/LaunchAgents/io.bastet.bsc.plist
  launchctl bootout   (tolerated: nothing loaded)  → bootstrap → kickstart -k
launchctl print gui/501/io.bastet.bsc      state = running · program = …/bsc · pid = 13612
GET /v1/vault/status                       {"sealed":true,…}
bsc doctor                                 ✅ daemon running · ✅ web ui with CSP · ✅ auto-start LaunchAgent present
kill -9 <pid 14870>                        launchd: state = spawn scheduled
  (6 s later) pgrep                        pid 14893 — KeepAlive restarted it; /v1/vault/status answers
bsc service uninstall                      bootout → plist removed → daemon down; vault untouched
~/Library/Logs/bsc/bsc.err.log             two "listening" lines, one per start
```

Two things learned and changed: the first attempt checked for the restart
after 3 s and saw `spawn scheduled`, because launchd's default
`ThrottleInterval` is 10 s — the plist now sets it to 2 s (unit-tested). And
the test harness's PID extraction used `\s` in `awk`, which macOS awk does not
support; `pgrep -f` is what the recorded run used.

This establishes: the definition loads, launchd supervises the process,
`KeepAlive` recovers from a hard kill within the throttle window, `doctor`
observes all of it, and uninstall leaves nothing but the log directory.

## The reboot test — not done, and why

The gate asks for one real-machine reboot survival test per platform. None
was performed:

- **macOS:** with the operator's go-ahead the LaunchAgent was installed,
  observed under launchd, hard-killed and watched restart, and then removed
  (above). `RunAtLoad` is set, so it will start at login — but a login after
  a reboot is a different event from a `kickstart`, and it has not been
  observed. The operator can do it in one sitting: `bsc service install`,
  reboot, `bsc doctor`.
- **Linux, Windows:** no real machine available. CI runners cannot reboot.
  The unit passes `systemd-analyze verify`; the Task Scheduler line is
  unit-tested but never executed.

Until this is done, "starts at login" is a claim about the definition, not an
observation. The master plan status table says so.

## Not done — explicitly

- **Reboot survival on any platform** (above). macOS got the closest thing
  short of a reboot; Linux and Windows got a linted definition only.
- **No code signing or notarization.** macOS Gatekeeper will warn on the
  downloaded binary until M7; the install script does not bypass that.
- **No installer packages** (`.pkg`, `.msi`, `.deb`). Archives only.
- **No tray process**, so no native notification actions; `OsNotifier` stays
  a shell-out.
- `install.sh` verifies against sums from the same release: integrity, not
  authenticity. Provenance attestations are generated by `release.yml` but
  nothing verifies them client-side yet.
- The workspace version is still `0.0.0`; artifacts are named accordingly.
  Choosing a first version and cutting a tag is a decision, not a build step.
- `release.yml` has never run; it is exercised only by review.

## CI evidence

| Run | Commit | Ubuntu | macOS | Windows | Artifacts ×3 | Hygiene |
| --- | --- | --- | --- | --- | --- | --- |
| _pending_ | — | — | — | — | — | — |
