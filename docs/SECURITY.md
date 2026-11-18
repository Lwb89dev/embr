# Security

> **Embr has not been independently audited and must not be described as production-ready.**
> It is pre-alpha software: a tested cryptographic core and vault, a daemon with authenticated local IPC
> and a permission engine, NIP-46 remote signing (off by default), a CLI and a desktop GUI; Linux is the only
> platform exercised by hand.
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

## Implemented and tested in Milestone 5 (NIP-46)
Details in `NIP46.md`; tests in `apps/embrd/tests/nip46*.rs` and `crates/embr-nip46/`.

| Property | Test |
|---|---|
| Off by default and **silent**: no network connection with defaults, with "enabled but no relays", after disable, after lock | `remote_signing_is_off_by_default_silent_and_follows_the_vault_lock`, `nothing_connects_until_relays_are_set…` |
| Transport key ≠ user key; the addressed transport key selects the account; a client of A cannot use B's key | `bunker_flow_…`, `a_client_cannot_use_another_accounts_transport_key` |
| `bunker://` secrets are single-use, expire, and a bad/missing/reused secret gives **no prompt** | `secrets_are_single_use_and_unpaired_clients_get_nothing` |
| Unpaired remote clients can only `connect`/`ping`; every operation still needs a grant or approval; decrypt flagged | `bunker_flow_…`, `secrets_are_single_use_…` |
| `nostrconnect://`: relays of a URI are contacted **only after approval**; rejected URIs never connect; hostile URIs refused | `nostrconnect_import_contacts_client_relays_only_after_approval` |
| Replay (same event id), stale/future `created_at`, forged signatures, wrong kind/addressee, undecryptable content are dropped before the policy engine; per-client rate limit applies **before decryption** and does not starve other clients | `hostile_events_are_dropped…`, `per_client_rate_limit_applies_before_decryption`, `replay_flood_and_relay_outage` |
| Relay outage → automatic reconnection and resubscription; NIP-42 AUTH answered with the transport key | `reconnects_after_the_relay_drops_everyone`, `nip42_auth_relays_are_supported…` |
| A lock answers in-flight remote requests, stops new ones, disconnects; pairings survive lock/unlock; revocation works | `revocation_blocking_and_lock_over_nip46` |
| Independent client interop (nostr-tools), both flows | `nip46_interop.rs` |

## Implemented and tested in Milestone 4 (desktop GUI, `embr`)
The GUI is a thin client of the control channel: it holds no key, stores nothing, and needs the vault password
(or the in-memory control token that dies with every lock) for everything.
| Property | Test |
|---|---|
| Against a real `embrd`: create vault, add account, lock clears the account list, a wrong password does not unlock, an app pairs, the user approves the *exact stored event*, the signature verifies, the log holds no message content | `backend::tests::*` (4) |
| With the vault locked, no screen shows an account, app or request text (the "unlocked by another client" and daemon-down states are not separately tested) | `ui::tests::a_locked_vault_shows_nothing_private` |
| Everything typed that is secret (vault password fields, `nsec`, NIP-49 password, export password) is zeroised whenever the vault is not unlocked | `ui::tests::locking_wipes_what_was_typed` |
| Drawing a screen sends no command to the daemon without a user action (clicks themselves are not simulated) | `ui::tests::every_screen_renders_and_drawing_alone_sends_nothing` |
| Every "remember" choice the UI offers is one the policy engine accepts (direct-message kinds: once/session only; any-kind: never permanent; unscoped decrypt: at most an hour) — a UX guarantee, the engine stays the authority | `ui::tests::every_choice_the_ui_offers_is_accepted_by_the_policy_engine` |
| Notifications carry the sanitised app name and the operation only; markup characters in the (untrusted) name are escaped on freedesktop servers | `notify::tests::*` |
| The tray helper sees only the vault state and a count of waiting requests from the unauthenticated `status`, notices a request arriving, and survives the daemon disappearing | `tray::tests::*` (incl. one against a real daemon) |

The GUI process also drops core dumps (`RLIMIT_CORE=0`; `NoNewPrivs` read back from `/proc` on Linux) and
calls the same `PR_SET_DUMPABLE=0` code as the daemon; I could not confirm non-dumpability from outside the
process, only that the call reported success.

**GUI limitations (not hidden):**
* egui's text fields keep their own copies (undo history, galley caches) of what was typed. Embr zeroises its
  own `String`s only; the GUI's memory is **not** `mlock`ed and may still contain a typed password until the
  process exits. The daemon, which holds the keys, is the hardened process; the GUI never holds one.
* **No anti-spoof word** (the threat model proposed one): the GUI cannot prove to the user that a prompt is
  genuine, and synthetic input on X11 can click "Approve". Wayland compositors block that by default.
* The GUI does not offer reveal-`nsec` (only the control API does).
* **The tray (`embr --tray`) exists on Linux only.** On Windows and macOS, with the window closed, requests are not
  announced and wait until they expire. The Linux helper holds no key, no password and no control token: it
  polls the daemon's unauthenticated `status` every 3 s (vault state and a *count* of waiting requests, never who
  asks or what for), shows that in the tooltip and raises a notification when the count rises while no window is
  open. Any process of the same user that can reach the control socket can read the same status, so the tray
  discloses nothing new. Tested against a real daemon and, by hand, on one desktop (quickshell: the icon
  registered with the StatusNotifierWatcher, its state and tooltip changed, one notification was sent); I have
  **not** seen the icon drawn, because that bar collapses tray icons behind a chevron I could not click.
* **Accessibility (AccessKit) is compiled in but has not been tested with a screen reader.**
* Desktop notifications are shown by the desktop's notification server, which can log them and show them on a
  locked screen; they contain only the app's name and the operation.
* Linux/Wayland on one machine is the only platform where the window has been looked at.
* `cargo deny` accepts three "unmaintained" advisories (`zvariant`, `zbus_names`, `zvariant_derive`,
  RUSTSEC-2026-0370/71/72) with a written reason and a review date (2027-03-01): they are reached only through
  eframe → AccessKit → AT-SPI, only in the GUI binary (checked: `embrd`/`embrctl`/libraries do not depend on
  them), and are about maintenance, not a vulnerability. The `time` advisory RUSTSEC-2026-0009 (macOS
  notification crate) was fixed by pinning `time` 0.3.47, which needs Rust 1.88 (the GUI needs 1.95 anyway).

## Findings while building Milestones 5–7
* **Connections the daemon ended were never closed (found 2026-11-18, via a hung macOS CI job; fixed).**
  In `client_api::serve` the original sender of the writer channel stayed alive, so after *any* end of a client
  connection (client EOF, idle timeout, five malformed lines, an oversized line, a NUL byte) the daemon waited
  for its writer task forever: the socket stayed open and the connection kept counting against
  `max_connections`. Effect: a client that connected and left, or a hostile one that sent junk, permanently used
  a slot and a file descriptor until the daemon restarted, so enough of them would have refused every new
  client (an availability problem; no key or permission was ever exposed). The control channel was not
  affected. Fix: drop the sender and bound the wait. The tests had passed because a read timeout was accepted
  as proof of closure; they now require a real close and a freed slot.
* **A fuzzer found a bug in relay-URL validation** (`nip46_uri`, within 40 s): the URL parser strips leading
  control characters and percent-encodes others; the length limit was checked on the raw input but the
  *normalised* (longer) form was what got stored and later failed re-validation. Fixed: control characters and
  whitespace are refused up front, host names are validated label by label, and the normalised length is bounded;
  the crash input is a regression test.
* **Lock vs in-flight remote requests:** stopping the relay service immediately at lock meant pending remote
  requests were never answered (the client hung). Now new requests stop at once, in-flight ones are answered, and
  the connection closes after a 0.75 s drain.
* **systemd sandbox vs NIP-46:** with the shipped `AF_UNIX`-only sandbox the relay cannot connect; the daemon
  reports it clearly and the CLI points at the documented drop-in (verified both ways).
* **`cargo-deny` on new dependencies:** the TLS stack needed an explicit, narrow exception for `ring` (only as
  rustls' provider) and the `CDLA-Permissive-2.0` data licence of the Mozilla root list (ADR-9).

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
* **Not verified for NIP-46:** `wss://` against a real public relay (TLS against an in-process relay with a throw-away certificate **is** tested, including refusal of unknown-authority, wrong-name and expired certificates: `crates/embr-nip46/tests/tls.rs`), interop with `nak`.
* **Milestone 3 gaps:** the Windows transport (named pipes with a user-only DACL) exists but has only run in CI; no spawn-bound
  clients; no `SO_PEERPIDFD`; passwords arrive in `String` fields of request structs (not zeroised;
  they also pass through `serde_json::Value`); the control token and client key files are plain
  same-user secrets; the audit log is an ordinary file; only minutes of fuzzing per target and no independent review.
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
Independent code review and audit · long-running fuzzing (5 minutes per target so far, see `TESTING.md`) · penetration test of the
IPC and approval flow · hand-testing on macOS/Windows · testing the GUI with a screen reader · reproducible builds · signed releases.

## Practices
* `#![forbid(unsafe_code)]` workspace-wide (exception: future `embr-platform`, each use justified).
* `clippy -D warnings` with `unwrap/expect/panic/indexing` warnings on; CI formatting check.
* Secrets only in `Zeroizing` types; never logged; never in argv; never in error messages.
* No telemetry, analytics, advertising or hidden network activity.
