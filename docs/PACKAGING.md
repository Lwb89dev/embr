# Packaging

> **Status (Milestone 6):** the files that build every package exist and are listed below with what has and has
> not been verified. **Nothing is signed, nothing is published (no AUR upload, no GitHub release), and no package
> has been installed on a machine I own except the Arch one.** Constraints the design already imposes:

* Native packages only; **no AppImage**. User-level service (never root): systemd `--user` unit on Linux,
  launchd agent on macOS, per-user Run entry/Scheduled Task on Windows — all optional, all wrapping the same `embrd` binary.
* Vault data lives in the user's data directory, **separate from binaries**; an ordinary uninstall never
  deletes it; upgrades never touch it; storage-format migrations write a new file and keep the old one
  until verified (see `ARCHITECTURE.md` §4).
* systemd unit hardening (from Omostrich's findings): `LimitCORE=0`, `NoNewPrivileges=true`,
  `ProtectSystem=strict`, `PrivateTmp=true`, explicit `ReadWritePaths`.
* One daemon per user (lock file) — packages must not start a second instance.
* The GUI loads Wayland, X11, GL and fontconfig with `dlopen`, so tools that follow `ldd` do not see them. The
  library list in every package was read from the binary (`strings embr | grep -o 'lib…\.so…'`) and is
  maintained by hand in `packaging/arch/PKGBUILD` and `apps/embr-desktop/Cargo.toml`.
* Icons: `scripts/make_icons.py` generates the hicolor PNG sizes (16–512), `embr.ico` (16–256) and `embr.icns`
  (16–1024) from `assets/icons/icon.png`; the results are committed (`packaging/icons/`) and
  `scripts/make_icons.py --check` verifies their structure byte by byte.
* macOS: Developer-ID signing and notarisation only when credentials are supplied; Windows: Authenticode likewise.
  No credentials exist, so those paths are written but **never executed**.

## What exists

| Artefact | Built by | Built and inspected locally | Installed and run |
|---|---|---|---|
| Arch `embr-git` | `packaging/arch/PKGBUILD` | yes (Omarchy) | `makepkg` + `check()` only; never `pacman -U` |
| `.deb` | `cargo deb` (metadata in `apps/embr-desktop/Cargo.toml`) | yes: file list, modes, `Depends` read back | see "Release workflow" below |
| `.rpm` | `cargo generate-rpm` (same manifest) | yes: file list, requires read back (`bsdtar`, `strings`; `rpm` is not installed here) | see below |
| Windows installer | NSIS, `packaging/windows/embr.nsi` | **no** (no Windows machine, no NSIS here) | see below |
| macOS `.app` / `.dmg` | `packaging/macos/build_app.sh` | **no** (no macOS machine) | see below |

### Release workflow (`.github/workflows/release.yml`)
Runs on `v*` tags or by hand. It builds each artefact on a clean GitHub runner **and then installs it there**:
`apt install ./embr_*.deb` on Ubuntu, `dnf install ./embr-*.rpm` in a Fedora container, a silent install →
run the installed programs → silent uninstall of the NSIS installer on a Windows runner, `hdiutil attach` →
run the binaries inside the `.dmg` on macOS. Each of those jobs also starts the installed daemon and asks it for
its status. It then writes CycloneDX SBOMs and `SHA256SUMS`; a tag run creates a **draft** pre-release with
provenance attestations (never published automatically). 

**Results of the run on commit `b6f3bfe` (2026-11-18, GitHub-hosted runners):**
| Job | Result | What it proves — and what it does not |
|---|---|---|
| `.deb` on Ubuntu 22.04, 24.04, latest, and Debian 12 | passed | `apt install ./embr_*.deb` resolved the declared dependencies, `embrd`/`embrctl`/`embr --version` ran, the `.desktop` file validated, every library the GUI `dlopen`s exists, the daemon started and `embrctl status` answered, removal worked. Does **not** prove the GUI window opens (no display on the runner). |
| `.rpm` on Fedora (container) | passed | same checks with `dnf`; openSUSE is **not** covered |
| Windows installer (`embr-0.0.1-setup.exe`, 5.1 MB) | passed | silent install, installed `embrd`/`embrctl` run, the installed daemon answers over its named pipe, shortcut and uninstall entry exist, silent uninstall removes files and registry key. Unsigned. Does **not** prove the GUI window opens, nor behaviour on Windows 10. |
| CycloneDX SBOMs, version check | passed | one SBOM per binary (`embrd`, `embrctl`, `embr-desktop`) |
| macOS `.dmg` (universal, `Embr-0.0.1-macos.dmg`) | passed (run on commit `9cdab2b`, the first macOS job GitHub gave a slot to) | both architectures built and merged with `lipo` (`x86_64 arm64`), `Info.plist` valid, ad-hoc signature verified, the `.dmg` mounted, `embrd`/`embrctl`/`embr --version` run from inside it, and the daemon started on macOS and answered `vault: Missing`. Ad-hoc signed only, **not notarised** (Gatekeeper will warn); does **not** prove the window opens, nor behaviour on Intel hardware or older macOS (the runner is Apple Silicon) |

Two things found only by running it on CI: (1) the first Windows run failed because NSIS was given a relative
script path and its `!cd` left the repository; (2) the first Linux run built the packages on the newest
Ubuntu, whose glibc is too new for 22.04/24.04 and Debian 12 — packages now build on `ubuntu-22.04`, the oldest
base, and are installed on all of the above.

## Details of the Arch and systemd checks (2026-11-17)

**`packaging/systemd/embrd.service`** (user unit)
* `systemd-analyze verify --user`: syntax ok (it only complains that `/usr/bin/embrd` is not installed yet).
* Run for real as a transient unit with the same properties under a *user* systemd (Omarchy): service
  **active**, sockets created `0600` in a `0700` runtime dir that is removed on stop, vault created `0600`
  in a `0700` data dir, `CapEff=0`, `NoNewPrivs=1`, seccomp filter active, core limit 0; inside the same
  sandbox `AF_UNIX` is allowed and `AF_INET`/`AF_INET6` sockets fail ("Address family not supported").
* Found by that test: `ReadWritePaths=` fails with `226/NAMESPACE` if the directory does not exist (a fresh
  user); fixed with `ExecStartPre=+/usr/bin/mkdir -p -m 0700 …`.
* NIP-46 (Milestone 5) will need `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`; remember to change it.

**`packaging/arch/PKGBUILD` (`embr-git`)** — see the verification notes in `docs/INSTALLATION.md`.
