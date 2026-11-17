# Architecture

*Status legend: **[built]** exists and is tested in this repository; **[next]** is the very next
milestone; **[planned]** is designed but not started.*

## 1. Product shape

Embr is a **desktop identity and signing application**: it holds Nostr private keys and performs
cryptographic operations for other applications. It is not a Nostr client, a browser extension
or a hosted service. Two ways in:

* **Local signing** (primary): native apps on the same machine talk to the signer over an
  authenticated, versioned local IPC — no relay, no network, works offline.
* **NIP-46 remote signing** (optional, off by default): standard `bunker://` / `nostrconnect://`
  so any NIP-46 client (including web apps) can use the signer.

## 2. Process model and trust boundaries

```
 ┌──────────────┐  client API (authenticated, per-client grants)   ┌───────────────────────────┐
 │ Native client│ ───────────── AF_UNIX / Named Pipe ────────────▶ │                           │
 │ (OUTKAST, …) │                                                  │      embrd  (daemon)      │
 └──────────────┘                                                  │  ───────────────────────  │
 ┌──────────────┐  NIP-46 (kind 24133, NIP-44)  ┌───────┐ outbound  │  embr-vault   (keys)      │
 │ Remote client│ ◀────────────────────────────▶│ relay │◀─────────▶│  embr-policy  (decisions) │
 └──────────────┘                               └───────┘ only when │  embr-ipc     (protocol)  │
                                                           enabled  │  embr-nip46   (transport) │
 ┌──────────────┐  control channel (privileged, separate endpoint) │  embr-platform(OS glue)   │
 │ embr (GUI)   │ ◀──────────────────────────────────────────────▶ │  audit log (metadata)     │
 │ embrctl (CLI)│   no keys, ever: shows requests, sends decisions  └───────────────────────────┘
 └──────────────┘
```

* **`embrd` is the only process that ever holds decrypted key material.** It runs as the user (never
  root), as a user-level service where available, and keeps serving previously authorised
  requests while the GUI is closed.
* **The GUI and CLI are thin clients of the control channel**, which needs the **vault password** (or a
  control token issued after it, kept in memory only and invalidated by every lock) — so a GUI restart
  while the daemon stays unlocked re-attaches with the token, and a stolen socket path is useless. They never receive keys; the
  frontend state contains public information and request metadata only.
* **Client API and control channel are different endpoints with different credentials.** A client
  cannot approve its own request, and a spoofed "approve" arriving on the client API is just an
  unknown method.
* **NIP-46 networking is a separate component** that is *not started* unless remote signing is
  enabled and configured; with it off, the binary opens no outbound connections at all.
* **No dependency on any desktop environment, init system or window manager.** systemd units,
  `.desktop` files, launchd agents and Windows Run keys are *packaging conveniences* over the same
  binaries; autostart is optional.

## 3. Crate layout

Adjusted from the brief (`signer-*` → `embr-*`, see ADR-4): the layout keeps the brief's
separation of concerns.

| Crate | Responsibility | Status |
|---|---|---|
| `embr-core` | Platform-independent vocabulary: `AccountId`, `Pubkey32`, `Operation`, `KeySecurity`, `AccountMeta`, safe-text rendering (`display::sanitize`). No crypto, no I/O. | **[built]** 10 tests |
| `embr-crypto` | `Identity` (owns a secret key); NIP-01 signing with strict templates; NIP-44; NIP-04 (legacy); NIP-19; NIP-49; limits. Thin wrapper over `rust-nostr`; **no custom primitives**. | **[built]** 27 tests + interop |
| `embr-vault` | Encrypted multi-account vault; backup/restore; password change; step-up exports; encrypted application blobs (policy, settings). | **[built]** 35 tests |
| `embr-policy` | Permission engine: default-deny, scoped grants (account × client × operation × kind × peer), expiry, session scope, use limits, rate limiter, audit record types. Pure logic. | **[built]** 24 tests |
| `embr-ipc` | Wire protocol: framing with size limit, handshake, client proof of possession (signed event), request/response types, error codes, control-channel types. No I/O. | **[built]** 21 tests |
| `embr-platform` | OS glue: private runtime/data directories, instance lock, process hardening, peer hints. Safe `rustix` wrappers only (no `unsafe` was needed). Unix only so far. | **[built]** 5 tests |
| `embr-client` | Blocking SDK for third-party Rust apps + control-channel client + client-key file helper. | **[built]**, example app |
| `embr-nip46` | NIP-46: URIs, NIP-44 JSON-RPC over kind 24133, small relay client (rustls, NIP-42 AUTH, reconnection), signer service with replay/freshness/rate-limit defences, in-process test relay. | **[built]** 12 tests + daemon e2e |
| `apps/embrd` | The daemon: two sockets, policy, approvals queue, audit log, idle auto-lock, throttled unlock. | **[built]** 23 tests (19 e2e) |
| `apps/embrctl` | CLI + terminal approval UI (`watch`). | **[built]** 1 e2e test |
| `apps/embr` | Desktop GUI (ADR-3). | **[planned]** |

Workspace lints: `unsafe_code = "forbid"` everywhere (relaxed only in `embr-platform`, each
`unsafe` block justified), `unwrap/expect/panic/indexing` warnings promoted to errors by CI.

## 4. Vault format (version 1) [built]

```
password ──Argon2id(m,t,p,salt)──▶ KEK ──XChaCha20-Poly1305(AAD=slot params)──▶ wrapped vault key
vault key ──XChaCha20-Poly1305(AAD=all slots)──▶ body = [fmt][len][meta JSON][secret_0 … secret_n]
```

* Secret keys are **outside the JSON** (raw 32-byte records) so they never pass through a generic
  parser. Metadata (labels, avatars, ids, active account, revision) is inside the encrypted body, so
  the file leaks neither labels nor public keys.
* `slots[]` is an array so that further unlock methods (OS keyring "device slot", hardware token)
  can be added without a format migration; only `password` exists today.
* Password change **rotates the vault key** and salt; atomic writes (temp file `0600` → `fsync` →
  rename → `fsync` dir); one previous generation is **not** kept (it would stay decryptable with the
  old password).
* Argon2id defaults: 256 MiB, t=3, p=4; bounds enforced on every read (≤ 1 GiB, t ≤ 16, p ≤ 16) so
  a hostile file cannot exhaust resources before authentication.
* NIP-49 `ncryptsec` is used for **interchange** (export/import), exactly as specified (scrypt),
  not for the internal format.
* **Policy and settings are stored inside the encrypted, authenticated body** (named blobs), not in a
  side file: malware running as the user cannot grant itself permissions by editing a JSON file; it
  would need the vault password (tested: `blobs_survive_password_change_and_backup_and_tampering_is_detected`).
* Versioning/migration: `version` is checked first; an unknown version is refused with
  `UnsupportedVersion` and the file is left untouched. A migration will always write a new file and
  keep the original until the new one is verified.

## 5. Key request lifecycle (local signing) [built, `apps/embrd`]

1. Client connects → server sends a handshake with a fresh nonce.
2. Client proves possession of its client key (BIP-340 signature over a domain-separated hash
   including the nonce). Unknown key ⇒ "unpaired" session.
3. Client sends `sign_event`. The daemon: parse strictly → check lock state → look up
   `(client, account, operation, kind)` in the policy engine →
   * **allow** (existing grant) → sign using the stored canonical request → audit record → reply;
   * **deny** (explicit *always reject*) → error `denied`;
   * **ask** → store canonical request in the pending queue, notify the control channel, wait.
4. The GUI shows the stored request; the user chooses a scope; the decision arrives on the control
   channel referencing request id + digest; the daemon signs and replies, or rejects.
5. Timeouts, client cancel, vault lock, account removal and disconnect all resolve the pending
   request with a structured error — never a hang.

## 6. Decisions (ADRs)

### ADR-1 — Rust, with a platform-independent core
*Decided.* Memory-safe, no GC (predictable secret lifetimes), mature crypto ecosystem, and
`rust-nostr` provides maintained protocol code. The core crates compile on all targets without
platform code. Alternatives considered: Go (NoorSigner, nak — fine, but no `zeroize`-style control and
a larger binary), Zig (Notary — promising, ecosystem too young for our crypto needs), JVM (Amber
Desktop — large, slow startup, bundled JDK).

### ADR-2 — Daemon / GUI / CLI split with two endpoints
*Decided.* Keys live in one small process; the GUI is replaceable (ADR-3 can change without touching
security-critical code); previously authorised requests work with no GUI; the control channel is a
separate endpoint so clients cannot approve. Compared with Omostrich's single control socket (no
per-app identity, unapproved `sign_internal`) and Notary's loopback HTTP + bearer, we use the same
transport primitives as the client API but different credentials and no TCP.

### ADR-3 — GUI toolkit: Slint (provisional) vs Tauri 2
*Provisional decision: **Slint**, to be confirmed by a measured spike before Milestone 4 ships.*
The measurements below are **deliberately blank**: I have not built either toolkit yet and will not
invent numbers. The spike procedure is in `BENCHMARKS.md`; the decision flips if the gates fail.

| Criterion | Slint | Tauri 2 | Evidence status |
|---|---|---|---|
| Executable size | *to measure* | *to measure* (excludes the system WebView) | spike |
| Idle RSS | *to measure* | *to measure* (WebKitGTK is multi-process) | spike |
| Startup latency | *to measure* | *to measure* | spike |
| Runtime deps on Linux | windowing (Wayland/X11), fontconfig/freetype; **no GTK, no WebView** | `webkit2gtk-4.1`, GTK3 (+ appindicator for tray) | known from each project's docs; webkit2gtk-4.1 / gtk3 are installed on the dev machine, so this machine would not reveal a missing-dependency problem — test on a clean Ubuntu/Fedora/openSUSE container |
| Distro reach | independent of GTK version | tied to distro WebKitGTK (needs 4.1: Debian ≥ 12, Ubuntu ≥ 22.04, Fedora, openSUSE) | documented |
| Tray / notifications | not built in: use `ksni` (pure-Rust StatusNotifierItem) on Linux, `tray-icon` on macOS/Windows, `notify-rust` | built-in tray API, notifications plugin | documented; M4 spike |
| Accessibility | AccessKit integration (maturity to be tested with Orca/NVDA/VoiceOver) | inherits the browser's a11y tree (generally the most mature) | **risk for Slint** — test with a real screen reader |
| Security boundary | no JS engine, no webview attack surface, no `npm` supply chain | CSP + capability allow-list; still a JS runtime and an HTML renderer processing untrusted event text | architectural |
| Rendering untrusted text safely | all text is inert by construction | must avoid `innerHTML`; strict CSP | architectural |
| Licence | GPL-3.0 **or** royalty-free desktop licence **or** commercial (**confirm terms on slint.dev before release**) | MIT / Apache-2.0 | **open decision, see below** |
| Maintainability | single Rust workspace, declarative `.slint` UI | Rust + web front-end (toolchain, dependency churn) | judgement |

*Why Slint is provisionally preferred:* the task description asks for a security utility with low
idle RAM, small installs and no heavyweight runtime; Slint has no web engine and no JS toolchain,
and a smaller attack surface for rendering untrusted text. *Why this may flip:* (a) screen-reader
support is inadequate in our test; (b) idle RSS/size advantage is not material in the spike;
(c) its licence is unacceptable.

**Open decision for the maintainer:** linking Slint under GPL-3.0 makes the *GUI binary* GPL-3.0
(libraries and daemon stay MIT; the combined work is GPL). The alternatives are Slint's royalty-free
desktop licence (attribution requirements) or Tauri (permissive). Because the GUI is only a client
of the control channel, this choice can be reversed later without touching key handling.

### ADR-4 — Crate names `embr-*` instead of `signer-*`
*Decided.* Generic names such as `signer-core` are unusable on crates.io and ambiguous in
dependency trees; a product prefix lets third parties depend on `embr-client`.

### ADR-5 — Licence: MIT
*Decided.* Same as `rust-nostr`, Amber, Notary, NoorSigner and Omostrich; maximal reuse by Nostr clients
that embed the SDK. `cargo-deny` rejects non-permissive dependencies (`deny.toml`).

### ADR-6 — Local protocol: JSON lines over a per-user stream socket, client-key proof-of-possession
*Draft; specified in `LOCAL_SIGNER_API.md`.* Framing and method names deliberately mirror
NIP-46/NIP-5F-draft so existing tooling can adapt; authentication is different on purpose (§3.A4 of
the threat model).

### ADR-7 — Reject, don't guess, on spec ambiguities
*Decided, from findings F1/F2 in `RESEARCH.md`.* Where independent implementations disagree (event ids
with control characters; NIP-44 plaintext > 65 535 bytes) the signer picks the interoperable
behaviour by default and makes the alternative an explicit, documented option.

### ADR-9 — TLS for relays: rustls with `ring`, only inside `embr-nip46`
*Decided (the maintainer did not answer the question, so the safest default was taken).* NIP-46 needs
`wss://`. OpenSSL/native-tls would add a C TLS stack to the trust base; `rustls` is memory-safe Rust. Its
crypto provider here is `ring` (not `aws-lc-rs`, which needs a heavier C/asm build). `deny.toml` therefore
allows `ring` **only as a dependency of `rustls`/`rustls-webpki`** and allows the `CDLA-Permissive-2.0`
data licence of the Mozilla root list. TLS only protects metadata in transit: NIP-46 payloads are
NIP-44-encrypted end to end, key material never touches `ring`, and a minimal hand-written relay client
(~300 lines) was preferred over pulling the full `nostr-sdk` relay pool (database layers, gossip, NIP-65).

### ADR-8 — MSRV follows security fixes, not the other way round
*Decided.* `rust-version = 1.87`, set because a RustSec advisory (`ctutils`, a constant-time
helper reached through `nostr → scrypt`) is only fixed in releases that need ≥ 1.87. Distribution
packaging builds with a pinned toolchain from `rust-toolchain.toml` and vendored dependencies
(`cargo vendor`), so old distro `rustc` versions are not a constraint.

## 7. What is deliberately absent
No telemetry, analytics, auto-update phone-home, advertising, hosted dependency or "cloud sync".
The binary performs **no network I/O** unless NIP-46 is enabled. Update checks, if ever added, will be
opt-in and are out of scope for now.
