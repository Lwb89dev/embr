# Security

> **Embr has not been independently audited and must not be described as production-ready.**
> It is pre-alpha software at Milestone 2 of 7: a tested cryptographic core and vault; no daemon,
> IPC, GUI or NIP-46 yet. Do not put a key you cannot afford to lose into any build of it.

Read `THREAT_MODEL.md` first: it states what is and is not defended against, especially regarding
malware running as the same user.

## Reporting a vulnerability
Use GitHub's **private vulnerability reporting** for https://github.com/Lwb89dev/embr (Security tab →
"Report a vulnerability"; the maintainer must enable it in the repository settings — if the button is
missing, open a minimal public issue asking for a private channel *without* details). Please include
the affected version/commit, impact (key exposure, unauthorised signing, denial of service…), and a
reproduction.

Supported versions: none are released; only the `main` branch receives fixes.

## Implemented and tested today (Milestone 2)
Each line links a property to the test that checks it.

| Property | Test |
|---|---|
| No custom cryptographic primitives; all crypto from `rust-nostr`, RustCrypto | architecture; `deny.toml` bans a second crypto stack (`ring`, OpenSSL) |
| Official NIP-44 test vectors pass (pinned checksum) | `crates/embr-crypto/tests/nip44_vectors.rs` |
| NIP-49 official vector decrypts; export/import round-trip; NFKC; cost bounded | `keys_nip19_nip49_nip04.rs` |
| NIP-01 ids match an *independent* serializer; signatures verify | `nip01_signing.rs` |
| Interoperates with `nostr-tools` in both directions | `interop.rs` + `tests/interop/run.sh` |
| A template cannot make an identity sign for another pubkey; client `id` verified, `sig` rejected, unknown fields rejected | `nip01_signing.rs` |
| Ambiguous-id control characters refused by default | `ambiguous_control_characters_are_refused_by_default` |
| Vault file contains no key, nsec, pubkey, label, avatar or password | `vault_file_leaks_neither_secrets_nor_metadata` |
| Every encrypted/authenticated field detects tampering; hostile KDF parameters refused instantly; truncated/garbage/oversize files rejected | `vault.rs` (`every_protected_field_is_authenticated`, …) |
| Locked vault refuses every operation | `everything_is_refused_while_locked` |
| Password policy enforced in the library; NFKC-normalised | `password_policy_*`, `passwords_are_nfkc_normalised` |
| Export of an `ncryptsec` or `nsec` requires the vault password again | `export_and_reveal_require_the_vault_password` |
| Files `0600`, directory `0700`, no temp files left, failed writes roll back, one winner in a create race | `files_and_directories_are_private`, `writes_leave_no_temporary_files`, `a_failed_write_rolls_back_memory_state`, `only_one_creator_wins_a_race` |
| `Debug` output never prints secrets | `debug_output_never_contains_secret`, `vault_debug_output_is_harmless` |
| Labels cannot contain control or bidi-override characters | `labels_are_validated` |
| Dependency advisories, licences, banned crates, sources are checked | `cargo deny check` (see below) |

**Mutation check (manual, 2026-11-17):** deliberately removing (a) rollback on failed write and
(b) the step-up password check each made a test fail; removing the KDF fields from the slot AAD did
*not*, because those fields already determine the KEK (so that AAD binding is defence in depth, not
the only barrier — documented in `format.rs`).

**Supply chain:** `cargo deny check` found a real RustSec advisory (`ctutils` 0.4.2, non-constant-
time mask generation, reached via `nostr → scrypt → pbkdf2 → hmac → digest`); fixed by updating
to 0.4.8, which required raising the MSRV to 1.87 (ADR-8). Now: advisories ok, bans ok, licences ok,
sources ok.

## Known limitations (also in the threat model)
* **Memory scrubbing is best-effort.** Secrets live in zeroising containers, but Rust cannot prove
  no other copy exists; swap, hibernation and core dumps are not yet blocked (daemon hardening is
  M3). The `argon2` crate's `zeroize` feature is enabled and wipes the initial hash and block hash
  (read in its source); I have **not** verified that the full 256 MiB memory matrix is wiped, and
  it is not `mlock`ed.
* **Password strength is the ceiling** for offline attacks: Argon2id raises the cost, not the entropy.
* **A copy of the vault made before a password change remains decryptable with the old password.**
* **Rollback of the whole vault file** to an older version is not detectable without external state.
* **No protection** against root/kernel compromise, or (see threat model) same-user malware that can
  read process memory or drive the UI.
* **`nostr` crate's `SecretKey` erasure is `non_secure_erase`** — best effort by its own name.
* NIP-04 is **legacy** (unauthenticated AES-CBC, metadata leaks). It is offered for compatibility
  only and will be labelled as such everywhere.

## Not yet done (must precede any "production-ready" claim)
Independent code review and audit · fuzzing of the parsers and IPC (M7) · penetration test of the
IPC and approval flow · platform tests on macOS/Windows · reproducible builds · signed releases.

## Practices
* `#![forbid(unsafe_code)]` workspace-wide (exception: future `embr-platform`, each use justified).
* `clippy -D warnings` with `unwrap/expect/panic/indexing` warnings on; CI formatting check.
* Secrets only in `Zeroizing` types; never logged; never in argv; never in error messages.
* No telemetry, analytics, advertising or hidden network activity.
