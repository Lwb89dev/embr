# Research and technical audit

*Milestone 1. Snapshot date: 2026-11-17.*

This document compares existing Nostr signers and libraries and records what we learned from them.
It follows one rule throughout: **a claim is labelled by how I know it.**

| Tag | Meaning |
|-----|---------|
| **[V]** | *Verified*: I read the code (or ran it) at the commit listed below. |
| **[D]** | *Documented*: stated in the project's README/docs; I did not verify it in code. |
| **[I]** | *Inferred* from code reading; plausible but not exercised. |

GitHub activity, stars or a project's own security notes are **not** evidence of an audit or of
production readiness. None of the projects below has an independent security audit that I could
find; absence from my search is not proof of absence.

## 0. Method and provenance

All repositories were shallow-cloned into an isolated scratch directory and read, not executed
(the only third-party code that was executed is `nostr-tools`, see §3.2). Commits examined:

| Project | Commit | Commit date | Language | LoC read |
|---|---|---|---|---|
| Amber (`greenart7c3/Amber`) | `b6a7912ba8` | 2026-11-17 | Kotlin (Android + JVM desktop) | desktop `core/*`, docs |
| nos2x (`fiatjaf/nos2x`) | `014493f960` | 2026-03-21 | JavaScript | all (~600 lines) |
| Alby extension (`getAlby/lightning-browser-extension`) | `91dba0a2ae` | 2026-10-27 | TypeScript | nostr actions, crypto, state |
| nak (`fiatjaf/nak`) | `f0c3d3ed43` | 2026-11-08 | Go | `bunker.go` |
| Omostrich (`ninepointlabs/omostrich`) | `453211b9bb` | 2026-10-27 | JavaScript/Node + QML | daemon, `TODO-security.md` |
| NoorSigner (`77elements/noorsigner`) | `0059bbd8e7` | 2026-01-30 | Go (3 122 lines) | all Go files (storage, daemon) |
| Notary (`zig-nostr/notary`) | `73e825c0ef` | 2026-10-14 | Zig | README, ARCHITECTURE, daemon onboarding |
| rust-nostr (`rust-nostr/nostr`) | `399fccfd88` | 2026-11-17 | Rust | `nostr` crate: keys, nips 01/04/44/49 |
| NIPs (`nostr-protocol/nips`) | `bec0fc89e7` | 2026-11-16 | Markdown | 01, 19, 44, 46, 49, 55 |

Note: the brief lists `rust-nostr/nostr-sdk` separately; the `nostr-sdk` crate now lives inside the
`rust-nostr/nostr` monorepo (`nostr-sdk/`), together with `signer/nostr-connect`.

## 1. Comparison matrix

Legend: ✅ implemented [V]; 📄 documented only [D]; ➖ not applicable; ❌ absent / not found.

| | Amber (Android) | **Amber Desktop** | nos2x | Alby ext. | nak bunker | Omostrich | NoorSigner | Notary |
|---|---|---|---|---|---|---|---|---|
| Platform | Android | Win/macOS/Linux (JVM) | Browser | Browser | CLI (any) | Omarchy only | macOS/Linux | macOS/Linux (GTK4) |
| Stack | Kotlin | Compose Desktop, JDK 21 | JS/WebExt | TS/WebExt | Go | Node + Quickshell | Go | Zig |
| License (file) | MIT¹ | MIT¹ | WTFPL² | MIT | Unlicense | MIT | MIT | MIT |
| Multiple accounts | ✅ [D] | ✅ [V] | ❌ [V] | ✅ (`state.ts` holds `accounts`) [V] | ❌ (1 key) | ❌ | ✅ [V] | ❌ (1 key file) |
| Key at rest | not examined (Android code not read) | AES-GCM + Argon2id passphrase lock; OS keyring holds passphrase [V] | **plaintext** in `browser.storage.local` [V] | crypto-js AES with password [V call, I mechanism] | supplied as nsec/hex/`ncryptsec` at start; on-disk handling with `--persist` not examined | AES-256-GCM, scrypt N=2¹⁷ [V] | AES-GCM, scrypt N=2¹⁴ [V] | NIP-49 `ncryptsec` [V] |
| Local IPC for native apps | NIP-55 intents/ContentProvider [D] | Unix socket, "NIP-5F" draft [V doc+code] | ➖ (NIP-07) | ➖ (NIP-07) | Unix socket for adding `nostrconnect://` clients [V] | Unix socket **without per-app identity** [V] | Unix socket, 0600 [V] | loopback HTTP + bearer [V doc] |
| Peer credential check | ➖ | `SO_PEERCRED` same-UID check (Linux/macOS) [V] | ➖ | ➖ | ❌ [I] | ❌ not found [V grep] | ❌ not found [V grep] | ➖ |
| Per-client identity | package name | secret (bearer, SHA-256 stored) [V doc] | origin host | origin | client pubkey + secret | none | none | NIP-46 client key |
| NIP-46 | ✅ [D] | ✅ + local loopback relay `ws://127.0.0.1:7777` [V doc] | ❌ | ❌ | ✅ [V] | ✅ via NDK [V] | **❌** — roadmap checkbox open, no code matches [V] | ✅ [V doc] |
| NIP-55 | ✅ [D] | ❌ (Android-only by design) | ➖ | ➖ | ➖ | ➖ | ➖ | ➖ |
| NIP-07 | ➖ | ➖ | ✅ | ✅ | ➖ | ➖ | ➖ | ➖ |
| NIP-44 / NIP-04 | ✅ / ✅ [D] | ✅ / ✅ + NIP-44 "v3" [V doc] | ✅ / ✅ [V] | ✅ / ✅ [V] | ✅ / ✅ [I] | ✅ / ✅ [V] | ✅ / ✅ [V] | not examined |
| Per-kind sign permission | ✅ [D] | ✅ [V doc] | per-method per-host [V] | per-origin [V: `permissions/`] | per-client only [I] | per-method **and kind** [V] | trust-mode only | allow once/day/always per client+kind [D] |
| Permission expiry | ✅ [D] | ✅ "5 minutes … always" [V doc] | ❌ [V] | not examined | ❌ [I] | ❌ (author notes it) [V] | 24 h "trust" session [V] | ✅ [D] |
| Approval UI | ✅ | ✅ | popup | popup | terminal log (no per-op prompt found) [I] | bar panel | terminal | native window |
| Auto-lock | not examined | passphrase lock [V]; auto-timeout not examined | ❌ [V] | not examined | ➖ | 5 min–24 h [D] | 24 h session [V] | on window close/exit [D] |
| Audit log | history [D] | history [V doc] | ❌ | ❌ | terminal | partial, sign_internal logged [V] | ❌ | JSON-lines audit file [V doc] |
| Reproducible builds | ✅ Docker + `desktopdiff.py` [V doc] | ✅ same | ❌ | ❌ | ❌ | ➖ | ❌ | CI-built, ad-hoc signed [D] |
| Maintenance (last commit) | active (today) | active | 2026-03 | active | active | 2026-10 | **2026-01 (stale)** | 2026-10 |
| Self-declared maturity | stable | stable | stable | stable | tool | v0.3.x | early | "early / work in progress" |

¹ Amber's `LICENSE` file is MIT but its README badge says Apache-2.0 **[V, inconsistent]**. Treat as
MIT only after clarifying with the maintainer if code is ever reused. We do not reuse Amber code.
² nos2x: `package.json` says WTFPL, README says "public domain"; there is no `LICENSE` file.

## 2. Per-project findings

### 2.1 Amber (and Amber Desktop) — primary functional reference

*The brief treats Amber as an Android app. It is not only that:* the repository contains
`:desktop` (Compose for Desktop on a bundled JDK 21), `:cli` (a NIP-46 client) and `:common`
**[V: `settings.gradle.kts`, `AGENTS.md`]**. This is the closest existing product to what we are
building, so the comparison below is deliberately detailed.

What it does well (and we adopt as *requirements*, not code):

* **One approval/permission engine for every transport** (intent, ContentProvider, NIP-46 relay,
  local socket) **[V: `docs/architecture.md`]**. We copy the principle: all entry points converge on
  a single `evaluate(request)` in the policy engine.
* **Permission model**: auto-accept/auto-reject per request type and event kind, time-boxed grants,
  per-app "basic / manual / full-trust" sign policies, history **[V: desktop README]**.
* **Local socket (the "NIP-5F" draft)** documented in `desktop/LOCAL_SIGNER.md` **[V]**:
  newline-delimited JSON, 1 MiB line limit, `get_public_key` doubles as login, errors 1–10,
  overlapping requests matched by `id`, pending requests expire after 10 min, locked signer answers
  error 10 immediately. Identity of a tool = a **32-byte random secret returned on first approval,
  stored hashed (SHA-256)**; name is only a label. Same-user enforcement: socket `0600` in a `0700`
  dir plus `SO_PEERCRED` uid comparison on Linux/macOS **[V: `PeerCredentials.kt`]**; on Windows
  none ("ACLs of the profile folder do the same job" — an assumption, not a verified control).
* **Key storage**: passphrase lock with **Argon2id** (BouncyCastle) and per-blob persisted cost
  parameters; OS keyring (macOS Keychain / Windows Credential Manager / Secret Service via
  `java-keyring`) *stores the passphrase-derived secret for convenience* **[V: `PassphraseLock.kt`,
  `KeystorePassword.kt`]**.
* **Reproducible desktop builds** with a Docker recipe and a verification script **[V doc]**.
* Local **loopback relay** (`ws://127.0.0.1:7777`) so NIP-46 clients on the same machine need no
  public relay **[V doc]** — a neat idea we note for NIP-46 (see `docs/NIP46.md` plan).

Shortcomings relative to our goals:

* **JVM + bundled JDK** ⇒ large install, high idle RSS; native `libamber_arti` (Tor) shipped as
  prebuilt binaries per OS **[V: `desktop/appResources`]** (Arti/Tor, judging by the name and `TorManager.kt` [I]) — a supply-chain surface.
* The socket secret is a **bearer token in a user-readable file**; any same-user process that can
  read it *is* the tool. Amber says so itself ("Treat it like a password") **[V doc]**. Embr's
  design (§ `LOCAL_SIGNER_API.md`) replaces it with a per-client **keypair proof-of-possession**,
  which is stronger against secret disclosure *in transit/logs* but — honestly — not against
  same-user malware that can read the client's private key file. See `THREAT_MODEL.md`.
* Windows has no peer-credential check.
* Desktop `BunkerEngine.kt` is 1 464 lines and duplicates Android logic; the maintainers list this
  as debt **[V: `docs/architecture.md`]**.
* Not on our Rust/no-JVM path; code reuse is impossible and not desired.

### 2.2 nos2x (NIP-07)

* **[V]** Private key is stored **in plaintext** in `browser.storage.local` under `private_key`
  (`background.js`, `performOperation`). No passphrase, no vault. This is the anti-pattern the
  Embr vault exists to avoid.
* **[V]** Permissions are keyed by the **host** of the calling page (`getPermissionStatus(host, type)`),
  with a prompt per request and optional "remember" conditions.
* **[V]** Uses `nostr-tools` for NIP-04 and NIP-44 v2.
* Takeaways for a *future* optional browser bridge: per-origin permissions, doing the
  encrypt/decrypt *before* asking so the prompt can show the result ("`do the operation before
  asking`", `background.js` ~L125). Do **not** copy: plaintext storage.

### 2.3 Alby browser extension (NIP-07 part only)

* **[V]** Nostr actions are split per operation with explicit `…OrPrompt` handlers
  (`signEventOrPrompt`, `nip44DecryptOrPrompt`, …) and a `permissions/` module including
  `isPermissionBlocked` — i.e. **an explicit "blocked" state distinct from "not yet asked"**. We
  adopt "Always reject" as a first-class decision.
* **[V call]** Account secrets are encrypted with `crypto-js` `AES.encrypt(data, password)`
  (`common/lib/crypto.ts`). That API's passphrase mode derives the key with an OpenSSL-style
  `EVP_BytesToKey` (single MD5 iteration) **[D: library behaviour, not traced here]** — a weak KDF
  by modern standards. Contrast: Embr uses Argon2id.
* Out of scope for us: all Lightning/wallet functionality.

### 2.3b nak `bunker`

* **[V]** `nak bunker` is a NIP-46 *server* around a single static key
  (`nip46.NewStaticKeySigner(sec)`), with `--authorized-keys`, `--authorized-secrets`, and optional
  `--persist` of authorised client pubkeys.
* **[V]** Authorisation is **per client** (`AuthorizeRequest(harmless, from, secret)`): a connecting
  client is accepted if its pubkey is already authorised or it presents a valid one-time/pre-shared
  secret (the "new secret" rotates after use). I found **no per-operation approval prompt** in the
  code I read; it logs requests to the terminal. [I: therefore effectively "trust the client"].
* **[V]** A Unix socket accepts `nostrconnect://` URIs from a local command to pre-authorise a
  client — a pattern worth considering for scripted pairing.
* Useful as an interop *peer* for testing our NIP-46 implementation (it is a different codebase in a
  different language). License: Unlicense (public domain).

### 2.4 Omostrich — Omarchy-specific

* **[V]** Node.js daemon + Quickshell/QML bar plugin; vault `AES-256-GCM` with
  `scrypt N=131072, r=8, p=1` (`daemon/vault.mjs`), `0600/0700` perms, key zeroing on lock.
* **[V] Trust boundary** (the brief asks us to pay attention): the Unix control socket has **no
  per-application identity** — only `0600`. I grepped the control socket code for `SO_PEERCRED` /
  peer-credential use and found none. Its own README describes the design as trusting "first-party
  plugins running as your own user". `sign_internal` signs **without an approval gate**; the
  maintainers' `TODO-security.md` records this as a deliberate decision that is "no longer
  invisible" (each call is logged) and notes a **residual gap: NIP-46 signatures bypass that audit
  path** because the NDK library signs directly.
* **[V]** Lessons worth adopting: `LimitCORE=0` (no core dump holds the key — their `systemd-coredump`
  finding), `NoNewPrivileges`, `ProtectSystem=strict` **[D: described in their `TODO-security.md`; I did not read the unit file]**; pass secrets on **stdin, not argv** (verified
  by reading `/proc/<pid>/cmdline`); grants scoped per **method and event kind** with kind 14/1059
  signs "warn and can't be remembered"; enforce password length in the vault, not only the UI;
  `npm ci`/lockfile discipline.
* **[V]** Has **no grant expiry** (author says so) and ties the vault to a Node/Quickshell/Omarchy
  stack — not portable.

### 2.5 NoorSigner

* **[V]** Go, 3 122 lines, MIT, last commit 2026-01-30. Multi-account, daemon + Unix socket `0600`,
  NIP-44 and NIP-04, autostart on macOS/Linux.
* **[V] NIP-46 is not implemented.** The README roadmap line `- [ ] NIP-46 Remote Signer support` is
  unchecked and a case-insensitive search of all Go sources for `nip46|bunker|nostrconnect|24133`
  returns **no matches**.
* **[V]** Vault KDF is `scrypt N=16384, r=8, p=1` (the weakest value in NIP-49's table is 2¹⁶),
  with AES-256-GCM.
* **[V] "Trust mode" weakness**: `createTrustSession` encrypts the nsec with a random 32-byte AES
  key and stores **that key (`SessionToken`) in the same `trust_session` file** next to the
  ciphertext. For the 24 h trust window the secret is therefore protected only by file permissions,
  not by the password. Our design never persists a decryption key beside its ciphertext.
* **[V]** No peer-credential check found in `daemon_unix.go` (socket mode `0600` only).

### 2.6 Notary — native, small, early

* **[D+V]** Zig throughout, **no WebView, no Electron**; GTK 4.10+ on Linux (Ubuntu 23.10+,
  Debian 13+, Fedora 39+; Ubuntu 22.04 and Debian 12 are **too old**) — a concrete example of the
  distribution-compatibility cost of a native toolkit. macOS via Metal.
* **[V]** Two processes: daemon (holds key, NIP-49 `ncryptsec` on disk, NIP-46 over relays) and GUI
  (never holds the key; talks to the daemon over **loopback HTTP with a bearer secret**).
  "Keyholder" mode passes the secret to the daemon **over stdin from the parent**, and states the
  reason explicitly: *file permissions do not isolate apps on the desktop*. We adopt this
  insight: an **inherited-descriptor/stdin capability** is stronger than a file-based token
  (see `LOCAL_SIGNER_API.md` §"spawn-bound clients").
* **[V]** JSON-lines **audit log** of every key use (never keys/passphrases/content).
* Self-declared "early / work in progress"; macOS builds are ad-hoc signed. Treat as an
  architectural reference, not a security-proven foundation (as the brief asks).
* Footprint figures in the README were **not** measured by me; none are repeated here.

### 2.7 rust-nostr — what we build on

* **[V]** `nostr` 0.45.7, MIT, MSRV 1.85, `no_std`-capable. Features we use: `nip04`, `nip06`,
  `nip44`, `nip49` (and `nip46` types later). `SecretKey` zeroes itself on `Drop` via
  `secp256k1::SecretKey::non_secure_erase` ("best effort" by name).
* **[V]** NIP-49 decryption **bounds the scrypt cost in untrusted input** (`MAX_LOG_N = 18` by
  default) — a DoS defence we mirror and make configurable (`Limits::max_ncryptsec_log_n`).
* **[V]** NIP-44 doc comments warn that decrypting near-`u32::MAX` payloads needs gigabytes and tell
  callers to impose their own limit; we do (`Limits::max_ciphertext_bytes`).
* **[V]** `nostr-connect` (NIP-46 client/signer, 0.45.3) and `nostr-browser-signer(-proxy)` exist in
  the monorepo — candidates for the NIP-46 milestone and for the optional NIP-07 bridge.
* **No code was copied** from any project; we depend on `nostr` as a library.

## 3. Specification review and findings

NIPs studied at `bec0fc89e7`: 01, 04, 06, 07, 19, 44, 46, 49, 55 (and 59 for gift-wrap workflows).

### 3.1 NIP-55 and "NIP-5F" are not the desktop answer
NIP-55 is explicitly *"Android Signer Application"* (intents, content resolver, web callbacks). It
cannot be implemented on a desktop and we do not pretend to. Amber Desktop's local socket follows a
**draft** called NIP-5F (`nostr-protocol/nips#1862`, cited by Amber's docs **[D]**); it is **not** in
the NIPs repository at the commit above (no `5F.md`). Embr's local protocol is therefore specified
in its own document; compatibility with the NIP-5F draft framing is a design goal (§
`LOCAL_SIGNER_API.md`) but not a promise.

### 3.2 Findings that change implementation (all verified by running code)

**F1 — NIP-01 id of events with C0 control characters is verifier-dependent.**
NIP-01 says only `\n \" \\ \r \t \b \f` are escaped in `content` and *"all other characters must be
included verbatim"*. JSON-library-based implementations escape the remaining C0 characters
(U+0000–U+001F) as `\u00XX`. I computed the event id for `content = "control \u0001 x"` with
(a) a literal reading of the spec and (b) `nostr-tools` 2.26.1 (`getEventHash`): they **differ**;
`rust-nostr` agrees with `nostr-tools`. For `\b \f \n \r \t` and U+007F all agree.
*Decision:* Embr **refuses by default** to sign templates containing the ambiguous characters
(`Limits::allow_ambiguous_control_chars`), because a signer must not emit signatures whose validity
depends on the verifier; when explicitly allowed it follows the JSON-library behaviour.
(Test: `ambiguous_control_characters_are_refused_by_default`; found by an independent serializer in
`tests/nip01_signing.rs`.)

**F2 — NIP-44 text and its checksummed test vectors disagree on maximum plaintext.**
The current `44.md` allows plaintext up to 2³²−1 bytes using a 6-byte extended length prefix for
≥ 65 536 bytes, and publishes an "extended length prefix" table. But the test-vector file whose
SHA-256 the same document pins (`269ed0f6…5040`, which is what `paulmillr/nip44` serves) still lists
65 536, 100 000 and 10 000 000 under `invalid.encrypt_msg_lengths`. `nostr-tools` 2.26.1 and
`rust-nostr` already accept > 65 535.
*Decision:* decryption accepts whatever the library accepts (bounded by our size limit);
**encryption defaults to ≤ 65 535 bytes** so that older recipients' clients can read it
(`Limits::max_plaintext_bytes`). Configurable. We pass all other official vectors.

**F3 — rust-nostr's bundled NIP-44 vector file is not the pinned one.** Its SHA-256 differs from
the NIP-pinned checksum and it contains fewer cases (e.g. 3 vs 35 `get_conversation_key`). We test
against the *pinned* file, not the library's copy.

**F4 — NIP-49 `ncryptsec` uses NFKC-normalised passwords.** We verified round-trips between
differently-normalised forms (spec example "ÅΩẛ̣") and that `nostr-tools` imports what we export and
vice-versa.

**F5 — NIP-46 has grown beyond the "classic" description:** `connect` carries optional requested
permissions and **client metadata** (name/url/icon), `switch_relays`, `auth_url` challenges, NIP-89
discovery, and `nostrconnect://` with a mandatory `secret`. Amber also implements a NIP-44 "v3"
(context-kind/scope) extension that is **not** in the NIPs at this commit; we do not implement it.

### 3.3 Independent interoperability (what was actually run)

* `nostr-tools` **2.26.1** (JS, Unlicense; pinned in `tests/interop/package-lock.json`; installed with
  `--ignore-scripts`).
* Direction 1: vectors generated by `nostr-tools` (events, NIP-44, NIP-04, NIP-49, NIP-19) are
  verified/decrypted/imported by Embr. Direction 2: artefacts produced by Embr (18 of them, incl. a
  65 535-byte NIP-44 message and an `ncryptsec` with a non-ASCII password) are accepted by
  `nostr-tools`. Reproduce with `tests/interop/run.sh`.
* **Not yet done:** interop with a second independent NIP-46 *client* such as `nak` (Amber is another signer,
  not a client, so it is not a counterpart for Embr as a signer).

## 4. Reusable libraries

| Need | Choice | License | Why / status |
|---|---|---|---|
| Nostr protocol (events, NIP-04/06/19/44/49) | `nostr` 0.45 | MIT | maintained monorepo, active; zeroising `SecretKey`; used as-is |
| secp256k1 / BIP-340 | via `nostr` → `secp256k1` | CC0 | libsecp256k1 bindings |
| Vault KDF | `argon2` 0.5 (RustCrypto) | MIT/Apache-2.0 | Argon2id; `zeroize` feature enabled |
| Vault AEAD | `chacha20poly1305` 0.10 (XChaCha) | MIT/Apache-2.0 | 192-bit random nonces |
| Zeroisation | `zeroize` 1 | MIT/Apache-2.0 | |
| Atomic files | `tempfile` 3 | MIT/Apache-2.0 | `persist_noclobber` for race-free create |
| Local IPC (planned) | `tokio` + `interprocess`/native `AF_UNIX`, `rustix` for `SO_PEERCRED` | MIT/Apache-2.0 | to be evaluated in M3 |
| NIP-46 transport (planned) | `nostr-connect`, `nostr-sdk` relay pool | MIT | to be evaluated in M5 |
| Linux keyring (planned) | `secret-service` / `keyring` crate | MIT/Apache-2.0 | opt-in only, see `SECURITY.md` |
| Notifications (used) / tray (not built) | `notify-rust` (used); `ksni` / `tray-icon` (evaluated on paper, not adopted) | MIT/Apache-2.0 | M4 |

Licence compatibility: everything above is MIT/Apache-2.0/CC0, compatible with Embr's **MIT**
licence, with two notes on the GUI binary (ADR-3: egui is MIT/Apache-2.0, but it bundles OFL-1.1 /
Ubuntu-Font-Licence fonts and, on Windows, BSL-1.0 crates, all accepted by name in `deny.toml`).

## 5. Consequences for Embr (summary)

1. **Rust, native, no JVM/WebView in the daemon.** Amber Desktop proves the product shape; Notary
   proves a small native executable is feasible; both also show the cost (JDK size; GTK ≥ 4.10).
2. **Never store a decryption key next to its ciphertext** (NoorSigner trust mode) and never store
   a private key in plaintext (nos2x).
3. **Authenticate clients by something stronger than a socket mode or a name** (Omostrich, NoorSigner),
   and be honest that same-user malware can still read same-user files (Amber, Notary say the same).
4. **One policy engine for every transport**, decisions scoped by account × client × operation × kind,
   with expiry and an explicit *always reject* (Amber, Alby, Omostrich).
5. **Harden the daemon process** (`LimitCORE=0`, no-new-privs, stdin not argv) — Omostrich's lessons.
6. **Do not trust spec prose alone:** F1/F2 were only found by testing against independent
   implementations and the pinned vectors.
