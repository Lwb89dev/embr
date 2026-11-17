# Packaging — plan

> **Status: not started (Milestone 6).** Constraints that the design already imposes:

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
