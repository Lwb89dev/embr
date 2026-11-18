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
The Linux packages ship a `.desktop` file and icons. `embr --tray` starts a small tray helper (Linux only: an icon, the
number of waiting requests, and a notification when one arrives while no window is open); to start it at login copy
`/usr/share/doc/embr/examples/embr-tray-autostart.desktop` to `~/.config/autostart/`. On Windows and macOS there is no tray and,
with the window closed, no notification. **Back up your keys** (`embrctl accounts export`): a forgotten vault
password cannot be recovered.

## Packages (Milestone 6)
| Platform | Format | Status |
|---|---|---|
| Debian / Ubuntu / Mint / Pop!_OS | `.deb` | built on Ubuntu 22.04 by the release workflow and installed and run with `apt` on Ubuntu 22.04, 24.04, latest and Debian 12 (`PACKAGING.md`); no release is published |
| Fedora / openSUSE | `.rpm` | built and installed with `dnf` in a Fedora container by the workflow; **openSUSE not covered** (library package names differ) |
| Arch / Omarchy / EndeavourOS / Manjaro | `PKGBUILD` (`embr-git`) | builds and tests locally and in CI; ships the daemon, CLI **and** the GUI; not on the AUR |
| macOS (Apple Silicon + Intel) | `.app` in a universal `.dmg` | built as a universal binary, mounted and run on a macOS runner (Apple Silicon); **ad-hoc signed only, not notarised**. To get a signed one, build it yourself with `packaging/macos/build_dmg.sh` and your own Developer ID (`PACKAGING.md`) |
| Windows 10/11 x64 | per-user NSIS installer | built, silently installed, run and uninstalled on a Windows runner; **unsigned** (SmartScreen warns); signing and hand-testing on a real Windows machine are planned for later |
| **AppImage** | **never** — explicitly excluded | — |

Targets are called *supported* only after a person tested a real installation: none is yet. The pipeline
proves "builds, installs, starts and answers" on a clean CI image, not "works on your desktop".

## Arch / Omarchy (from the repository's PKGBUILD)
```bash
git clone https://github.com/Lwb89dev/embr.git && cd embr/packaging/arch
makepkg -si                                  # builds, runs the test-suite, installs embrd, embrctl and the user unit
systemctl --user enable --now embrd.service
embrctl init && embrctl accounts add main && embrctl watch
```
The package installs `/usr/bin/embrd`, `/usr/bin/embrctl`, `/usr/bin/embr` (the GUI) with its `.desktop` file,
icons and AppStream metainfo, `/usr/lib/systemd/user/embrd.service`, the licence and the docs. It never touches `~/.local/share/embr` (your vault) — not on upgrade, not on removal.

**Verified (2026-11-17, Omarchy):** `makepkg -f --nodeps` against a local clone built the package, ran the
whole test-suite in `check()` (152 tests, 0 failed) and produced a 2.5 MiB `embr-git-…-x86_64.pkg.tar.zst`
containing exactly the files listed above; the extracted `embrd`/`embrctl` run. `--nodeps` was needed only
because this machine gets `cargo` from rustup rather than pacman, so the `makedepends` check itself was not
exercised here (CI builds it in a clean `archlinux` container with the real `rust` package — that job has not
run yet). Found by this test: without `options=('!lto')` the link fails with undefined `rustsecp256k1_*`
symbols (makepkg's `-flto` CFLAGS vs the C library built by the `cc` crate). Not tested: installation with
`pacman -U` (needs root), the `.install` hooks, `systemctl --user enable` from the installed unit, aarch64.
