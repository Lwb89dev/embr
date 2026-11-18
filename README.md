<p align="center"><img src="assets/icons/icon.png" alt="Embr" width="128" height="128"></p>

<h1 align="center">Embr</h1>
<p align="center"><b>A native, cross-platform Nostr signer for the desktop.</b><br>
Your private key stays in one small, encrypted, local process. Apps ask it to sign — they never see the key.</p>

> **Status: pre-alpha.** Cryptographic core, encrypted vault, permission engine, signer daemon with
> authenticated local IPC, NIP-46 remote signing (off by default), client SDK, a terminal control/approval
> CLI and a desktop GUI (egui) with a Linux tray helper are built and tested on Linux. Packages exist for Arch,
> `.deb`, `.rpm`, a Windows installer and a macOS `.dmg`, each built and install-tested on GitHub's runners. The Windows transport (named pipes) is implemented and its CI
> job is green, but nobody has run it on a real Windows machine; macOS has only ever run on CI runners (the full test suite passes there, 204 tests, after a daemon bug that a hung macOS job exposed was fixed; the packaged programs start and the daemon answers; see `docs/TESTING.md`). **Nothing is
> signed or published, and there is no tray on Windows or macOS.**
> It has **not been audited** — do not trust it with a key you cannot afford to lose.
> Read [`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## What it is (and is not)

Embr aims to be "Amber for Linux, macOS and Windows": install one signer, create or import your Nostr
identity once, and authorise desktop apps — or remote NIP-46 apps — to sign and encrypt on your
behalf, with per-app, per-kind, expiring permissions.

It is **not** a Nostr client, a browser-only extension, a wallet or a hosted service. It has no telemetry,
no analytics and no mandatory cloud. Local signing works fully offline; NIP-46 relay networking is
off unless you turn it on.

> Closest existing product: **Amber Desktop** (Compose/JVM). Embr differs by being native Rust
> (no bundled JDK), authenticating local clients by key proof-of-possession, and keeping the
> daemon, GUI and CLI strictly separate. See [`docs/RESEARCH.md`](docs/RESEARCH.md).

## Where we are

| Milestone | Scope | State |
|---|---|---|
| 1 | Research, threat model, architecture, workspace | **done** (this repo) |
| 2 | Crypto core, encrypted vault, accounts, import/export, tests | **done** — official vectors, interop with `nostr-tools` |
| 3 | Daemon, authenticated local IPC, policy engine, SDK, example client, CLI | **done on Linux**; Windows named pipes implemented (CI green, not hand-tested); on macOS the full suite (204 tests) passes on a CI runner |
| 4 | Desktop GUI, approvals, tray, notifications | **done on Linux** — egui app (`embr`): unlock, accounts, approvals, apps and permissions, remote signing, activity, notifications; plus `embr --tray`, a small resident tray icon (Linux only) that shows how many requests wait and notifies you while the window is closed. **No tray on Windows or macOS**: there, with the window closed, nothing notifies you and requests wait (and expire). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ADR-3 |
| 5 | NIP-46 remote signing | **done on Linux** — `bunker://` + `nostrconnect://`, interop with nostr-tools ([`docs/NIP46.md`](docs/NIP46.md)) |
| 6 | `.deb`, `.rpm`, Arch `PKGBUILD`, Windows installer, macOS `.dmg` (no AppImage) | **built and install-tested on CI**: `.deb` (Ubuntu 22.04/24.04/latest, Debian 12), `.rpm` (Fedora), Windows installer, universal macOS `.dmg`; Arch package builds; **nothing is signed or notarised, nothing is published** ([`docs/PACKAGING.md`](docs/PACKAGING.md)) |
| 7 | Fuzzing, benchmarks, dependency review, release docs | **done as far as it goes**: 8 fuzz targets (minutes each, 1 bug found), measured benchmarks, a [dependency review](docs/DEPENDENCIES.md) (not a source audit), release docs. **No independent audit, no long fuzzing campaign, no signed release** |

### Try it (Linux/macOS, from source)
```bash
cargo build --release -p embrd -p embrctl
target/release/embrd &                      # the signer daemon (user-level, never root)
target/release/embrctl init                 # create the vault (asks for a password)
target/release/embrctl accounts add main    # a new identity, generated inside the vault
cargo run -p embr-client --example login_and_sign &   # a native app asks to log in and sign…
target/release/embrctl watch                # …and you approve (pairing, signing, encryption) here
```
Apps integrate with [`embr-client`](crates/embr-client) (Rust) or the line-delimited JSON
protocol in [`docs/LOCAL_SIGNER_API.md`](docs/LOCAL_SIGNER_API.md) from any language.

### Works today
* Local signing for native apps over an authenticated Unix socket: client-key proof of possession,
  default-deny pairing, per-account / per-client / per-kind permissions (once, session, until, persistent,
  always reject), revocation, rate limits, safe rendering of what is being signed, audit log (metadata only).
* Idle auto-lock, immediate lock, throttled unlock, process hardening (no core dumps, non-dumpable).

### Library level
* Generate / import `nsec` / import hex / import & export NIP-49 `ncryptsec` (spec vector verified).
* Multi-account vault: Argon2id + XChaCha20-Poly1305, encrypted backup & restore, password change
  with key rotation, step-up re-authentication for exports, auto-lock hooks (`lock()`).
* NIP-01 signing with strict template validation, NIP-44 (official vectors), NIP-04 (legacy), NIP-19.
* Interop in both directions with an independent implementation (`nostr-tools` 2.26.1).

## Build and test
```bash
# Rust is pinned in rust-toolchain.toml (rustup installs it automatically)
cargo test --workspace            # 180 tests (the e2e suites take ~45 s)
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check                  # licences, advisories, bans, sources
tests/interop/run.sh              # two-way interop with nostr-tools (needs Node ≥ 20)
cargo run --release -p embr-vault --example kdf_bench   # measure unlock cost on your machine
```
See [`docs/DEVELOPER_GUIDE.md`](docs/DEVELOPER_GUIDE.md) and [`docs/TESTING.md`](docs/TESTING.md).

## Documentation
| | |
|---|---|
| [`RESEARCH.md`](docs/RESEARCH.md) | Comparison of Amber, nos2x, Alby, nak, Omostrich, NoorSigner, Notary, rust-nostr; spec findings |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, actors, what is and is not protected |
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Process model, crates, vault format, decisions (ADRs) |
| [`LOCAL_SIGNER_API.md`](docs/LOCAL_SIGNER_API.md) · [`CONTROL_API.md`](docs/CONTROL_API.md) | Local protocol for native apps; privileged channel for GUI/CLI |
| [`SECURITY.md`](docs/SECURITY.md) | What is tested, known limits, reporting |
| [`TESTING.md`](docs/TESTING.md) · [`BENCHMARKS.md`](docs/BENCHMARKS.md) | What runs, what was measured |
| [`NIP46.md`](docs/NIP46.md) · [`INSTALLATION.md`](docs/INSTALLATION.md) · [`PACKAGING.md`](docs/PACKAGING.md) · [`RELEASE.md`](docs/RELEASE.md) | Plans and status for the later milestones |

## Licence
MIT (see [`LICENSE`](LICENSE)). The GUI toolkit (egui) is MIT/Apache-2.0; the GUI binary additionally bundles
fonts under OFL-1.1 and the Ubuntu Font Licence, recorded as per-crate exceptions in `deny.toml` (ADR-3 in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)).
