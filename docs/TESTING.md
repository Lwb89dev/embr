# Testing

## Running
```bash
cargo test --workspace                  # unit + integration + e2e (151 tests at Milestone 3; ~30 s)
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
| `embrctl` e2e | 1 | the CLI against a real daemon, including terminal approvals |

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
* No GUI or NIP-46 tests exist because those components don't yet.
* The e2e suite uses real time for expiry/auto-lock (≈2 s waits); it passed 3 consecutive runs on
  2026-11-17 on Linux, but timing tests can flake on a heavily loaded CI machine.
* Unix sockets only: Windows named pipes (and their DACL) are untested because unwritten.
* **No fuzzing yet** (planned M7: `cargo-fuzz` on the template parser, vault envelope parser, IPC
  framing, NIP-46 message parser).
* No test of OS suspend/resume, SIGKILL/crash recovery beyond stale-socket cleanup, package upgrade/uninstall.
* Interop with `nak`, Amber, or any NIP-46 implementation: not yet.
* No timing/side-channel testing of our own code (we rely on libsecp256k1/RustCrypto).
