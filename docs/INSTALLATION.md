# Installation

> **No installable package exists yet.** Build from source (below); Linux/macOS only.

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
Linux and macOS only (Unix sockets). The `embr` GUI arrives in Milestone 4; there is no systemd
unit, `.desktop` file or package yet (Milestone 6). **Back up your keys** (`embrctl accounts export`):
a forgotten vault password cannot be recovered.

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
