# Developer guide

## Layout
```
crates/embr-core      shared vocabulary (no crypto, no I/O), safe-text sanitiser
crates/embr-crypto    Identity: signing, NIP-44/04/19/49, strict templates, limits
crates/embr-vault     encrypted multi-account vault
crates/embr-policy    permission engine (default-deny grants, expiry, rate limits, audit record types)
crates/embr-ipc       wire + control protocol types, framing, handshake proof
crates/embr-platform  OS glue: runtime dirs, instance lock, process hardening, Windows pipes (the only `unsafe`)
crates/embr-client    blocking SDK for apps + control-channel client
crates/embr-nip46     NIP-46 (URIs, JSON-RPC over kind 24133, relay client, signer service)
apps/embrd            the daemon
apps/embrctl          CLI and terminal approval UI
apps/embr-desktop     the GUI (binary `embr`): backend.rs (worker threads + Snapshot), ui.rs (pure drawing
                      functions returning commands), demo.rs (canned data), notify.rs, main.rs
fuzz/                 cargo-fuzz targets (detached workspace, nightly)
packaging/            systemd unit, Arch PKGBUILD
tests/vectors         official/independent test vectors (provenance in docs/TESTING.md)
tests/interop         two-way interop with nostr-tools (Node)
docs/                 research, threat model, architecture, specs
assets/icons          application icon (1254×1254 PNG; platform icon sets are generated at packaging time)
```

## Working on the GUI
* `cargo run -p embr-desktop -- --demo [approvals|accounts|apps|remote|settings|activity]` shows every screen
  with canned data and **no daemon** (nothing connects anywhere). Without `--demo` it connects to the control
  socket (`--control-socket PATH` to override); start a throw-away daemon with
  `embrd --data-dir /tmp/x/d --runtime-dir /tmp/x/r` (keep the socket path short: Unix socket paths are
  limited to about 100 bytes and `embrd` refuses longer ones).
* `ui::ui(root, &Snapshot, &mut UiState) -> Vec<Cmd>` is a pure function of its inputs: the UI never talks to
  the daemon. That is what the headless tests exploit (`egui::Context::run_ui` + reading the drawn text).
  `backend.rs` is the only code that opens a socket; its tests start a real in-process `embrd`.
* The GUI must never hold a key and must wipe typed secrets when the vault is not unlocked
  (`UiState::wipe_secrets`); new text fields for secrets need `.password(true)` **and** to be added to it.
* Anything shown that came from an app (name, event content) is already sanitised by the daemon; do not
  render it as markup, and escape it for notification servers (`notify::for_body`).
* The GUI needs Rust 1.95 (egui 0.37); `cargo build -p embrd -p embrctl` still works on 1.87.

## Rules of the house
1. **No custom cryptography.** Use `nostr`, RustCrypto, libsecp256k1. New primitives need an ADR.
2. **Secrets live in `Zeroizing<…>` or `Identity` and nowhere else**; never in `String` fields of public
   structs, logs, errors, argv, or `Debug` output.
3. **Parse strictly, fail closed.** `deny_unknown_fields`; explicit limits; no `unwrap/expect/panic/indexing`
   in library code (clippy enforces); `unsafe` is forbidden outside `embr-platform`.
4. **Test against something independent**, not only round-trips: official vectors, an independent
   reimplementation of the spec text, or another library (see the F1/F2 findings that this found).
5. When a spec is ambiguous, pick the interoperable behaviour by default and make the other an explicit
   option (ADR-7).

## Using the libraries (Rust)
```rust
use embr_crypto::{EventTemplate, Limits};
use embr_vault::Vault;

let mut vault = Vault::create("/path/to/vault.embr", "a long passphrase")?;   // unlocked; Argon2id default cost
let acct = vault.add_generated("main")?;                                     // key never leaves the vault
let limits = Limits::default();
let tpl = EventTemplate::from_json(r#"{"kind":1,"content":"hello nostr"}"#, &limits)?;
let event = vault.with_identity(acct.id, |id| id.sign_event(&tpl, &limits))??;
vault.lock();                                                                // wipes keys from memory
```
A runnable version: `cargo run -p embr-vault --example quickstart`.
(Application code normally talks to the *daemon* through the SDK `embr-client`, not to the vault directly.)

## Reproducible build
`rust-toolchain.toml` pins the compiler; `Cargo.lock` is committed; CI builds with `--locked`.
Bit-for-bit reproducible release artefacts (and a verification script like Amber's `desktopdiff.py`)
are a Milestone 6/7 goal and are **not** claimed today.
