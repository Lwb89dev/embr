# Security

> **Embr has not been independently audited and must not be described as production-ready.**
> It is pre-alpha software at Milestone 3 of 7: a tested cryptographic core and vault, a daemon with
> authenticated local IPC and a permission engine, a CLI; no GUI or NIP-46 yet, Linux/macOS only.
> Do not put a key you cannot afford to lose into any build of it.

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

## Implemented and tested in Milestone 3 (daemon, IPC, policy)
All of these are exercised end to end against a real `embrd` on real sockets
(`apps/embrd/tests/e2e.rs`, 19 tests, run 3× to check for flakiness), unless noted.

| Property | Test |
|---|---|
| Unknown clients can do nothing but `ping` and request pairing; pairing grants nothing by itself | `unknown_clients_can_do_nothing_but_ping_and_pair`, `login_pairing_and_signing_end_to_end` |
| Handshake: proof signed by another key, **replayed hello**, stale clock, no hello, wrong version are all refused; silent connections are dropped | `handshake_rejects_bad_proofs_replays_and_silence`, `stale_clock_proofs_are_rejected` |
| Malformed IPC (garbage, unknown fields, bad/duplicate ids, array params, NUL, >1 MiB line) is contained; 5 malformed lines in a row end the connection; the daemon keeps serving others | `malformed_and_hostile_ipc_is_contained` |
| Control-channel methods do not exist on the client socket; the control socket needs the vault password | same test; `exports_need_the_password_and_clients_cannot_reach_the_control_channel` |
| Cross-account isolation: a client cannot sign as, or even probe for, an account it was not granted (identical error) | `accounts_and_clients_are_isolated` |
| A grant to one client/account never applies to another | same |
| Decrypt is never implied by a signing grant; unscoped persistent decrypt and persistent DM-kind grants are refused (request stays pending) | `decrypt_is_never_implied_by_signing_and_sensitive_grants_are_refused` + `embr-policy` invariant test over all choices |
| What is approved is what is signed: decisions must echo the digest of the stored request | same |
| Prompts show sanitised text (bidi overrides, zero-width, controls made visible); ambiguous-id events refused before any prompt | `prompts_show_sanitised_content_and_encryption_works` |
| Session / timed / persistent grants and *always reject* behave and expire; persistent grants and pairings survive a daemon restart (stored encrypted in the vault) | `grants_session_timed_persistent_and_revoked` |
| Revocation, blocking (even mid-prompt) | same; `a_blocked_client_cannot_even_connect` |
| A lock cancels pending requests, wipes policy/tokens/keys from memory, invalidates control tokens and authenticated connections | `locking_cancels_pending_requests_and_blocks_everything` |
| GUI restart while the daemon stays unlocked; wrong passwords throttled | `gui_restart_while_the_daemon_stays_unlocked` |
| Idle auto-lock follows **user** activity, not auto-allowed client traffic | `idle_auto_lock_follows_user_activity_not_client_traffic` |
| Pending caps, per-client rate limit with `retry_after_ms`, request expiry, `cancel`, disconnect cleanup | `rate_limits_pending_caps_expiry_and_cancel` |
| 8 clients pairing and signing at once, each prompt naming the right account | `many_clients_pair_and_sign_concurrently` |
| Single instance, stale-socket cleanup, socket `0600`, directories `0700`, SDK refuses a group/world-accessible endpoint directory | `single_instance_stale_sockets_and_permissions` |
| Audit log holds metadata only (no content, no signatures) | `login_pairing_and_signing_end_to_end`, CLI test |
| Process hardening of the real binary: `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `NO_NEW_PRIVS` | `embr-platform` test (checks `/proc`), manual run |

## Findings while building Milestone 3
* **serde quirks that weaken "strict parsing":** `deny_unknown_fields` is *not* enforced for unit
  variants of internally tagged enums, and a struct also deserialises from a JSON *array*. Both were
  caught by tests and fixed (`DecisionRaw` intermediate type; `parse_params` requires an object).
* **`NO_NEW_PRIVS` is per-thread.** Applied after the async runtime started, worker threads would not
  have it. The binary now hardens in `main()` before any thread exists; the test reads
  `/proc/thread-self/status`.
* **Event-forwarder lifetime:** a subscribed control connection leaked its writer task after the
  client left, and could drop the `locked` notification in a race. Fixed with a per-connection
  cancellation token and an epoch check.
* **A dependency licence slipped in:** `dirs` → `option-ext` (MPL-2.0). `cargo deny` flagged it against
  our policy; the three-line replacement lives in `embr-platform`.

## Known limitations (also in the threat model)
* **Milestone 3 gaps:** no Windows transport (named pipes with a user-only DACL); no spawn-bound
  clients; no `SO_PEERPIDFD`; passwords arrive in `String` fields of request structs (not zeroised;
  they also pass through `serde_json::Value`); the control token and client key files are plain
  same-user secrets; the audit log is an ordinary file; only smoke-level fuzzing and no independent review.
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
Independent code review and audit · long-running fuzzing (only 40 s smoke runs so far, see `TESTING.md`) · penetration test of the
IPC and approval flow · platform tests on macOS/Windows · reproducible builds · signed releases.

## Practices
* `#![forbid(unsafe_code)]` workspace-wide (exception: future `embr-platform`, each use justified).
* `clippy -D warnings` with `unwrap/expect/panic/indexing` warnings on; CI formatting check.
* Secrets only in `Zeroizing` types; never logged; never in argv; never in error messages.
* No telemetry, analytics, advertising or hidden network activity.
