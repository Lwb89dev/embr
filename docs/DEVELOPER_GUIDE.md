# Developer guide

## Layout
```
crates/embr-core     shared vocabulary (no crypto, no I/O)
crates/embr-crypto   Identity: signing, NIP-44/04/19/49, strict templates, limits
crates/embr-vault    encrypted multi-account vault
tests/vectors        official/independent test vectors (provenance in docs/TESTING.md)
tests/interop        two-way interop with nostr-tools (Node)
docs/                research, threat model, architecture, specs
assets/icons         application icon (1254×1254 PNG; platform icon sets are generated at packaging time)
```

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
(Application code normally talks to the *daemon*, not to the vault directly; the daemon arrives in
Milestone 3 and the client SDK `embr-client` with it.)

## Reproducible build
`rust-toolchain.toml` pins the compiler; `Cargo.lock` is committed; CI builds with `--locked`.
Bit-for-bit reproducible release artefacts (and a verification script like Amber's `desktopdiff.py`)
are a Milestone 6/7 goal and are **not** claimed today.
