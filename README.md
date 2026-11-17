<p align="center"><img src="assets/icons/icon.png" alt="Embr" width="128" height="128"></p>

<h1 align="center">Embr</h1>
<p align="center"><b>A native, cross-platform Nostr signer for the desktop.</b><br>
Your private key stays in one small, encrypted, local process. Apps ask it to sign — they never see the key.</p>

> **Status: pre-alpha, Milestone 2 of 7.** The cryptographic core and the encrypted vault are built
> and tested. There is **no daemon, no IPC, no GUI, no NIP-46 and no installable package yet.**
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
| 2 | Crypto core, encrypted vault, accounts, import/export, tests | **done** — 66 tests, interop with `nostr-tools`, `cargo-deny` clean |
| 3 | Daemon, authenticated local IPC, policy engine, SDK, example client | next (protocol drafted: [`docs/LOCAL_SIGNER_API.md`](docs/LOCAL_SIGNER_API.md)) |
| 4 | Desktop GUI, approvals, tray, notifications | planned |
| 5 | NIP-46 remote signing | planned |
| 6 | `.deb`, `.rpm`, Arch `PKGBUILD`, Windows installer, macOS `.dmg` (no AppImage) | planned |
| 7 | Fuzzing, benchmarks, dependency review, release docs | planned |

### Works today (library level)
* Generate / import `nsec` / import hex / import & export NIP-49 `ncryptsec` (spec vector verified).
* Multi-account vault: Argon2id + XChaCha20-Poly1305, encrypted backup & restore, password change
  with key rotation, step-up re-authentication for exports, auto-lock hooks (`lock()`).
* NIP-01 signing with strict template validation, NIP-44 (official vectors), NIP-04 (legacy), NIP-19.
* Interop in both directions with an independent implementation (`nostr-tools` 2.26.1).

## Build and test
```bash
# Rust is pinned in rust-toolchain.toml (rustup installs it automatically)
cargo test --workspace            # 66 tests
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
| [`LOCAL_SIGNER_API.md`](docs/LOCAL_SIGNER_API.md) | Draft local protocol for native clients |
| [`SECURITY.md`](docs/SECURITY.md) | What is tested, known limits, reporting |
| [`TESTING.md`](docs/TESTING.md) · [`BENCHMARKS.md`](docs/BENCHMARKS.md) | What runs, what was measured |
| [`NIP46.md`](docs/NIP46.md) · [`INSTALLATION.md`](docs/INSTALLATION.md) · [`PACKAGING.md`](docs/PACKAGING.md) · [`RELEASE.md`](docs/RELEASE.md) | Plans and status for the later milestones |

## Licence
MIT (see [`LICENSE`](LICENSE)). The GUI toolkit decision may make the *GUI binary* GPL-3.0; see ADR-3 in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
