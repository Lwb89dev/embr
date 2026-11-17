# Installation

> **No installable package exists yet.** Only a development checkout is possible today.

## From source (developers)
Linux/macOS/Windows with `rustup` (the pinned toolchain installs itself):
```bash
git clone https://github.com/Lwb89dev/embr.git && cd embr
cargo test --workspace
```
There are no binaries to install until Milestone 3 (`embrd`, `embrctl`) and Milestone 4 (`embr` GUI).

## Planned packages (Milestone 6)
| Platform | Format | Status |
|---|---|---|
| Debian / Ubuntu / Mint / Pop!_OS | `.deb` | not started |
| Fedora / openSUSE | `.rpm` (each tested on its own distro) | not started |
| Arch / Omarchy / EndeavourOS / Manjaro | `PKGBUILD` (+ AUR source) | not started |
| macOS (Apple Silicon, Intel) | `.app` + `.dmg`, signing/notarisation workflow | not started |
| Windows 10/11 x64 | per-user installer (MSI or NSIS) | not started |
| **AppImage** | **never** — explicitly excluded | — |

Targets will be labelled *supported* only after a test on a real installation; cross-compiled-only
targets will be listed as untested.
