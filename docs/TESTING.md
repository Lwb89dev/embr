# Testing

## Fuzzing
```bash
cargo install cargo-fuzz --locked && rustup toolchain install nightly --profile minimal
cargo +nightly fuzz run ipc_lines -- -max_total_time=300     # targets: ipc_lines event_template vault_file policy_json crypto_inputs auth_proof
```

## Running
```bash
cargo test --workspace                  # unit + integration + e2e (180 tests; ~45 s)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                        # advisories, licences, bans, sources (needs: cargo install cargo-deny --locked)
tests/interop/run.sh                    # needs Node >= 20; installs nostr-tools 2.26.1 with --ignore-scripts
```

## What exists (verified on 2026-11-17, Linux x86-64, rustc 1.100.0)

| Suite | Tests | What it proves |
|---|---:|---|
| `embr-core` unit | 5 | id round-trip/uniqueness, operation names = NIP-46 method names, decrypt ≠ sign |
| `embr-crypto/nip44_vectors` | 8 | the **official, checksummed NIP-44 vectors** (valid + invalid) via the library and via the public API; tamper/wrong-peer/size-limit rejection |
| `embr-crypto/nip01_signing` | 9 | event id equals an **independent NIP-01 serializer** for control chars/quotes/unicode over 10 kinds; strict templates; pubkey/id checks; limits; ambiguity policy |
| `embr-crypto/keys_nip19_nip49_nip04` | 10 | NIP-19 doc vectors; strict key parsing; NIP-49 official vector, NFKC, cost bounds, wrong password; NIP-04 legacy |
| `embr-crypto/interop` | 2 | accepts what `nostr-tools` produces; `nostr-tools` accepts what Embr produces (`run.sh`) |
| `embr-vault/vault` | 32 | lifecycle, lock enforcement, tamper detection of each field, hostile files, atomicity, permissions, backup/restore, password change, rollback, create race |

| `embr-core` unit | 10 | + `Pubkey32`, safe-text sanitiser |
| `embr-vault/vault` | 35 | + encrypted blobs (policy/settings) incl. tamper & rollback |
| `embr-policy` | 24 | default-deny, scoping, session/timed/use-limited grants, deny precedence, sensitive-kind rules, an exhaustive invariant test, persistence & hostile stored data, rate limiter |
| `embr-ipc` | 21 | framing limits, strict wire types, client proof (replay, stale, wrong key, wrong kind), decisions, settings |
| `embr-platform` | 5 | private directories, instance lock, hardening visible in `/proc` (child process) |
| `embr-client` | 2 | client-key file creation/permissions |
| `embrd` unit + **e2e** | 4 + **19** | real daemon, real sockets: pairing, grants, isolation, lock, restart, concurrency, hostile IPC, limits (see `SECURITY.md` for the list) |
| `embrctl` e2e | 2 | the CLI against a real daemon: terminal approvals; opt-in remote signing and `bunker://` + QR |
| `embr-nip46` unit | 11 | URI parsing (hostile URIs), NIP-44 JSON-RPC protocol (strictness, addressing, forged events), relay-URL regression from a fuzzer finding |
| `embr-nip46/service` | 7 | the signer service against an in-process relay: round trip, replay, stale/future, rate limit before decryption, NIP-42 AUTH, reconnection after an outage, silence without relays |
| `embrd/nip46` e2e | 7 | NIP-46 through the real daemon: bunker pairing, signing and encryption with approvals, single-use secrets, account isolation by transport key, `nostrconnect://` (relays contacted only after approval), off-by-default/lock behaviour, revocation, replay/flood/outage |
| `embrd/nip46_interop` | 2 | **nostr-tools `BunkerSigner` (independent JS client)** via `bunker://` and `nostrconnect://` |

**Mutation check (manual):** three deliberate defects were injected into the vault; two were
caught by tests, one (AAD over KDF fields) is redundant by design and was documented as such.

## Official vectors used
* NIP-44: `tests/vectors/nip44.vectors.json` — SHA-256 `269ed0f6…5040`, the checksum pinned in the NIP.
* NIP-49: the decryption vector in the NIP (`password = "nostr"`, `log_n = 16`).
* NIP-19: the `nsec`/`npub` examples in the NIP.
* NIP-01 has no formal test vectors; we compare against an independent implementation of the
  serialization rules and against `nostr-tools` (which found finding F1 in `RESEARCH.md`).

## Not yet covered (honest list)
* macOS and Windows have **never been run** — the CI matrix exists but has not executed. Unix-only
  tests (`0600`/`0700`) are `cfg(unix)`; the atomic-create race test is unverified on Windows.
* **GUI coverage is partial.** `embr-desktop` has 20 tests: 13 render each screen headless through egui
  (nothing is drawn to a display) and check what is on screen and which commands come out, and 4 run the GUI's
  backend against a **real `embrd`** on real sockets (create vault, lock/unlock, wrong password, pair an SDK
  client, approve, verify the signature, daemon appearing late), and 3 check the notification text (names escaped for markup, metadata only). Not covered: real window rendering (checked by
  hand with screenshots on one Hyprland/Wayland machine), mouse and keyboard interaction (no click is simulated),
  screen readers, desktop notifications, X11, and everything on macOS and Windows.
* NIP-46 `wss://` (TLS) is **not exercised** by any test (all use loopback `ws://`); real public relays are untested.
* The e2e suite uses real time for expiry/auto-lock (≈2 s waits); it passed 3 consecutive runs on
  2026-11-17 on Linux, but timing tests can flake on a heavily loaded CI machine.
* Windows named pipes are implemented with a user-only DACL; the `windows-latest` CI job passed on commit
  `a6d9421`, but I have not looked at the per-test output and nobody has run it on a real Windows machine.
  macOS CI had not finished when this was written.
* **Fuzzing is minimal so far.** `fuzz/` holds eight libFuzzer targets (IPC framing + every strict wire type,
  event templates incl. sign-and-verify, vault file parsing, stored policy JSON with a default-deny/DM-kind
  invariant, key/ciphertext parsing, handshake proofs, NIP-46 URIs/relay URLs, NIP-46 events). The first six ran
  40 s each and the NIP-46 ones 60 s each (after a fix, see below) on 2026-11-17: ≈26 M executions in total.
  **The NIP-46 URI target found a real bug within its first 40 s** (relay URL validation); after the fix both
  NIP-46 targets ran clean. Still a smoke test, not assurance. No seed corpora, no structure-aware
  mutators, no sanitizers beyond libFuzzer's defaults. A weekly 5-minute-per-target CI run is configured but has
  not executed yet. NIP-46 message parsing will get its own target with Milestone 5.
* No test of OS suspend/resume, SIGKILL/crash recovery beyond stale-socket cleanup, package upgrade/uninstall.
* Interop with `nak`, Amber, or any NIP-46 implementation: not yet.
* No timing/side-channel testing of our own code (we rely on libsecp256k1/RustCrypto).
