# Dependency review

> **What this is and is not.** A review of *what* Embr depends on, *why*, under *which licence*, and what the
> automated gates say. It is **not an audit of the dependencies' source code**: I did not read their code, and
> a clean `cargo deny` run says nothing about vulnerabilities nobody has reported yet. Every dependency is a
> trust decision; the fewer, the better.

## Gates that run on every push
* `cargo deny check` (`deny.toml`, job `supply-chain`): licences (allow-list; exceptions are per crate with a
  reason), RustSec advisories (vulnerabilities, unmaintained, yanked), banned crates, registry sources
  (crates.io only, no git dependencies), wildcard version requirements.
* `gitleaks` over the full history (job `secrets`).
* `Cargo.lock` is committed and every CI build uses `--locked`; every GitHub Action is pinned to a full
  commit SHA.

## Direct dependencies
<!-- BEGIN GENERATED -->
Graph: **555 packages** in total (including build/dev/platform-specific ones), 30 direct external dependencies, 11 workspace crates.

| Dependency | Version | Licence | Used by | Why |
|---|---|---|---|---|
| `argon2` | 0.5.3 | MIT OR Apache-2.0 | `embr-vault` | Argon2id password hashing for the vault key (RustCrypto) |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | `embr-crypto`, `embr-vault` | encoding of ciphertext/blobs |
| `chacha20poly1305` | 0.10.1 | Apache-2.0 OR MIT | `embr-vault` | XChaCha20-Poly1305 vault encryption (RustCrypto) |
| `clap` | 4.6.8 | MIT OR Apache-2.0 | `embrctl` | command-line parsing for `embrctl` |
| `eframe` | 0.37.0 | MIT OR Apache-2.0 | `embr-desktop` | the desktop GUI toolkit (egui): window, rendering, accessibility |
| `futures-util` | 0.3.34 | MIT OR Apache-2.0 | `embr-nip46`, `embrd` | async helpers for the relay client |
| `getrandom` | 0.3.4 | MIT OR Apache-2.0 | `embr-core`, `embr-ipc`, `embr-nip46`, `embr-vault`, `embrd` | operating-system randomness (nonces, salts) |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | `embr-core`, `embr-crypto`, `embr-ipc`, `embr-nip46`, `embr-vault`, `embrd` | hex encoding of keys and ids |
| `ksni` | 0.3.7 | Unlicense | `embr-desktop` | system tray icon (StatusNotifierItem over D-Bus), Linux only, `embr --tray` |
| `nostr` | 0.45.7 | MIT | `embr-crypto`, `embr-nip46` | Nostr events, keys, NIP-01/04/06/19/44/49 (rust-nostr; all signing and NIP crypto) |
| `notify-rust` | 4.17.0 | MIT/Apache-2.0 | `embr-desktop` | desktop notifications (metadata only) |
| `qrcode` | 0.14.1 | MIT OR Apache-2.0 | `embr-desktop`, `embrctl` | QR code of a `bunker://` link |
| `rcgen` | 0.14.7 | MIT OR Apache-2.0 | `embr-nip46` | throw-away TLS certificates for the test relay (feature `testing`; in no shipped program) |
| `rpassword` | 7.5.5 | Apache-2.0 | `embrctl` | reading a password without echo in `embrctl` |
| `rustix` | 1.1.6 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | `embr-platform` | safe wrappers over Unix system calls (hardening, locks, sockets) |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | `embr-nip46` | TLS for `wss://` relays (ring provider; see ADR-9) |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | `embr-client`, `embr-core`, `embr-crypto`, `embr-ipc`, `embr-nip46`, `embr-policy`, `embr-vault`, `embrd` | (de)serialisation of every wire and storage type |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | `embr-client`, `embr-core`, `embr-crypto`, `embr-desktop`, `embr-ipc`, `embr-nip46`, `embr-policy`, `embr-vault`, `embrctl`, `embrd` | JSON for the protocols and the vault |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | `embr-crypto`, `embrd` | SHA-256 digests (request digests, hashed secrets) |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 | `embr-client`, `embr-desktop`, `embr-platform`, `embr-vault`, `embrctl`, `embrd` | temporary files and atomic writes; temporary directories in tests |
| `thiserror` | 2.0.21 | MIT OR Apache-2.0 | `embr-client`, `embr-core`, `embr-crypto`, `embr-ipc`, `embr-nip46`, `embr-policy`, `embr-vault`, `embrd` | error types |
| `tokio` | 1.54.1 | MIT | `embr-desktop`, `embr-ipc`, `embr-nip46`, `embr-platform`, `embrctl`, `embrd` | async runtime of the daemon, relay client and tests |
| `tokio-rustls` | 0.26.6 | MIT OR Apache-2.0 | `embr-nip46` | TLS over tokio streams |
| `tokio-tungstenite` | 0.30.0 | MIT | `embr-nip46`, `embrd` | WebSocket client/test relay |
| `tokio-util` | 0.7.20 | MIT | `embr-nip46`, `embrd` | cancellation tokens |
| `unicode-normalization` | 0.1.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | `embr-vault` | NFKC normalisation of passwords (NIP-49) |
| `url` | 2.5.8 | MIT OR Apache-2.0 | `embr-nip46` | parsing of `bunker://`, `nostrconnect://` and relay URLs |
| `webpki-roots` | 1.0.12 | CDLA-Permissive-2.0 | `embr-nip46` | the Mozilla CA root list as data, for `wss://` |
| `windows-sys` | 0.59.0 | MIT OR Apache-2.0 | `embr-platform` | Windows named pipes and security descriptors (Windows only) |
| `zeroize` | 1.9.2 | Apache-2.0 OR MIT | `embr-crypto`, `embr-desktop`, `embr-nip46`, `embr-vault`, `embrd` | wiping secrets from memory |

Distinct crates each binary pulls in at run time (`cargo tree -p X -e normal`, current host):

| Binary | Crates |
|---|---|
| `embrctl` | 124 |
| `embrd` | 157 |
| `embr-desktop` | 314 |
<!-- END GENERATED -->

Regenerate with `scripts/dep_report.py` (needs only Python 3 and cargo).

## Review notes (written by hand, 2026-11-18)
* **Cryptography.** No custom primitives. Signing, NIP-04/19/44/49 and key handling come from `nostr`
  (rust-nostr, which uses libsecp256k1 through `secp256k1`); the vault uses RustCrypto's `argon2` and
  `chacha20poly1305`; randomness is the OS's (`getrandom`). `ring` is in the graph **only** as the TLS provider
  of `rustls` and `deny.toml` bans it everywhere else (ADR-9). It never sees a key.
* **Network.** The daemon links a TLS/WebSocket stack (`rustls`, `tokio-tungstenite`, `webpki-roots`) but
  opens no connection unless NIP-46 remote signing is enabled and the vault is unlocked.
* **Daemon and CLI do not depend on the GUI.** `cargo tree -p embrd` and `-p embrctl` contain none of
  `eframe`, `egui`, `winit`, `zbus`, `accesskit` (checked). The GUI's much larger graph (see the table above)
  is a separate binary.
* **Accepted advisories (all GUI-only).** `zvariant`, `zbus_names`, `zvariant_derive` (RUSTSEC-2026-0370/71/72,
  "unmaintained", merged into zbus 6) arrive through eframe → AccessKit's AT-SPI backend. Accepted in
  `deny.toml` with a reason and a review date of 2027-03-01. `time` was bumped to 0.3.47 for RUSTSEC-2026-0009
  (reached only through the macOS notification crate).
* **Licences needing a decision.** The GUI binary bundles fonts under OFL-1.1 and the Ubuntu Font Licence
  (`epaint_default_fonts`) and, on Windows, two BSL-1.0 crates (`clipboard-win`, `error-code`); `webpki-roots`
  is CDLA-Permissive-2.0 data. All are permissive, all are per-crate exceptions or named allowances in
  `deny.toml`; nothing copyleft is in the tree.
* **Several versions of the same crate are in the lock file.** Ours use `thiserror` 2.x and `getrandom` 0.3, but
  other dependencies bring `thiserror` 1.x and `getrandom` 0.2 and 0.4; `nostr`/`bip39` bring two
  `bitcoin_hashes` (0.14, 1.2); the GUI adds many more duplicates. `cargo deny` warns about them (they are not
  errors). They add size, and a duplicate means two code bases to watch for advisories.
* **Unsafe code.** `unsafe` is forbidden in every workspace crate except `embr-platform`, which allows it only
  in `src/windows.rs` (named pipes and security descriptors). Dependencies contain plenty; not reviewed.
* **Not done:** a source review of any dependency; `cargo vet`/`cargo crev`; reproducible builds; checking
  maintainers' 2FA/publishing practices; a policy for dependency updates beyond "deliberate, with CI".
