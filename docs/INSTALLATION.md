# Installation

> **No installable package exists yet** (the Arch `PKGBUILD` installs the daemon and CLI only). Build from source (below).

## From source (developers)
Linux/macOS/Windows with `rustup` (the pinned toolchain installs itself):
```bash
git clone https://github.com/Lwb89dev/embr.git && cd embr
cargo test --workspace
```
```bash
cargo build --release -p embrd -p embrctl      # binaries in target/release/
install -Dm755 target/release/embrd target/release/embrctl ~/.local/bin/   # optional
embrd &                       # user-level daemon; sockets in $XDG_RUNTIME_DIR/embr/
embrctl init                  # create the vault; then: embrctl accounts add <label>
embrctl watch                 # approve requests from apps in the terminal
```
The desktop app is a separate binary, `embr` (needs Rust 1.95; the rest of the workspace builds with 1.87):
```bash
cargo build --release -p embr-desktop     # target/release/embr
embr                                      # starts without a daemon: shows "daemon not running" and a Start button
embr --demo [screen]                      # canned data, no daemon, for looking around (screens: approvals, accounts, apps, remote, settings, activity)
```
There is no `.desktop` file or tray icon yet, and no package ships the GUI (Milestone 6). With the window
closed there are no notifications. **Back up your keys** (`embrctl accounts export`): a forgotten vault
password cannot be recovered.

## Planned packages (Milestone 6)
| Platform | Format | Status |
|---|---|---|
| Debian / Ubuntu / Mint / Pop!_OS | `.deb` | not started |
| Fedora / openSUSE | `.rpm` (each tested on its own distro) | not started |
| Arch / Omarchy / EndeavourOS / Manjaro | `PKGBUILD` (`embr-git`) | **exists**, build tested locally (see below); not on the AUR yet |
| macOS (Apple Silicon, Intel) | `.app` + `.dmg`, signing/notarisation workflow | not started |
| Windows 10/11 x64 | per-user installer (MSI or NSIS) | not started |
| **AppImage** | **never** — explicitly excluded | — |

Targets will be labelled *supported* only after a test on a real installation; cross-compiled-only
targets will be listed as untested.

## Arch / Omarchy (from the repository's PKGBUILD)
```bash
git clone https://github.com/Lwb89dev/embr.git && cd embr/packaging/arch
makepkg -si                                  # builds, runs the test-suite, installs embrd, embrctl and the user unit
systemctl --user enable --now embrd.service
embrctl init && embrctl accounts add main && embrctl watch
```
The package installs only `/usr/bin/embrd`, `/usr/bin/embrctl`, `/usr/lib/systemd/user/embrd.service`,
the licence and the docs. It never touches `~/.local/share/embr` (your vault) — not on upgrade, not on removal.

**Verified (2026-11-17, Omarchy):** `makepkg -f --nodeps` against a local clone built the package, ran the
whole test-suite in `check()` (152 tests, 0 failed) and produced a 2.5 MiB `embr-git-…-x86_64.pkg.tar.zst`
containing exactly the files listed above; the extracted `embrd`/`embrctl` run. `--nodeps` was needed only
because this machine gets `cargo` from rustup rather than pacman, so the `makedepends` check itself was not
exercised here (CI builds it in a clean `archlinux` container with the real `rust` package — that job has not
run yet). Found by this test: without `options=('!lto')` the link fails with undefined `rustsecp256k1_*`
symbols (makepkg's `-flto` CFLAGS vs the C library built by the `cc` crate). Not tested: installation with
`pacman -U` (needs root), the `.install` hooks, `systemctl --user enable` from the installed unit, aarch64.
