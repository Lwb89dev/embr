# Packaging — plan

> **Status (Milestone 6, partial):** the systemd user unit and an Arch `PKGBUILD` exist and were tested
> as described below. `.deb`, `.rpm`, macOS `.dmg`, Windows installer, AUR publication and signed releases are
> **not started**. Constraints the design already imposes:

* Native packages only; **no AppImage**. User-level service (never root): systemd `--user` unit on Linux,
  launchd agent on macOS, per-user Run entry/Scheduled Task on Windows — all optional, all wrapping the same `embrd` binary.
* Vault data lives in the user's data directory, **separate from binaries**; an ordinary uninstall never
  deletes it; upgrades never touch it; storage-format migrations write a new file and keep the old one
  until verified (see `ARCHITECTURE.md` §4).
* systemd unit hardening (from Omostrich's findings): `LimitCORE=0`, `NoNewPrivileges=true`,
  `ProtectSystem=strict`, `PrivateTmp=true`, explicit `ReadWritePaths`.
* One daemon per user (lock file) — packages must not start a second instance.
* Dependency differences to resolve per distro (GUI libraries depend on ADR-3), dependencies vendored
  with `cargo vendor` so builds are offline and reproducible.
* Icons: generated from `assets/icons/icon.png` (1254×1254 RGBA) into `.ico`, `.icns` and the
  hicolor PNG sizes at packaging time.
* macOS: Developer-ID signing and notarisation only when credentials are supplied; Windows: Authenticode likewise.

## What exists and what was verified (2026-11-17)

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
