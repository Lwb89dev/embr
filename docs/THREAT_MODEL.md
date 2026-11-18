# Threat model

*Status: updated at Milestone 3. Items marked **(implemented)** are covered by code and tests in this
repository today (see `SECURITY.md` for the test names); everything else is a design requirement that
the corresponding milestone must satisfy and test. Nothing here is a security guarantee of a released
product: Embr has had no independent review.*

## 1. What we protect

| Asset | Why it matters |
|---|---|
| **Private keys** (secp256k1) | A Nostr identity is not recoverable or revocable in the base protocol. Loss of confidentiality = permanent impersonation. |
| **The ability to sign / decrypt as the user** | Even without the key, a process that can ask the signer to sign anything *is* the user. |
| **Plaintext of decrypted messages** | A decrypt operation hands private conversations to the caller. |
| **Vault password** | Unlocks everything; typed into our UI. |
| **Metadata**: account list, labels, which apps are paired, request history | Privacy; also helps targeting. |

## 2. Actors and capabilities

| # | Actor | Can do |
|---|---|---|
| A1 | **Offline attacker** with a copy of the vault file (stolen laptop, cloud-synced home directory, leaked backup) | Unlimited offline guessing. |
| A2 | **Another OS user** on the same machine | Connect to sockets, read world-readable files, but runs under a different uid. |
| A3 | **Buggy or over-eager legitimate app** | Sends malformed/huge/flooded requests; asks for more than the user intended; races the UI. |
| A4 | **Unprivileged malware running as the *same* user** | Read/write the user's files, connect to the user's sockets, spawn processes, and — depending on OS hardening — read the memory of the user's other processes and drive the UI. |
| A5 | **Remote attacker over NIP-46** (only when remote signing is enabled) | Send events to relays; replay, impersonate a client, flood, or try to learn the signer's pubkey. |
| A6 | **Network attacker** | Observe/modify relay traffic (relays are untrusted by NIP-46's design). |
| A7 | **Malicious Nostr content** | Crafted event content/tags shown in approval prompts (spoofing, bidi tricks, huge payloads). |
| A8 | **Privileged attacker** (root, kernel, hypervisor, physical access with DMA/cold-boot) | Anything. |

## 3. Security objectives and honest limits per actor

### A1 — offline attacker (**largely mitigated**)
* Vault is `Argon2id → KEK → wraps vault key → XChaCha20-Poly1305` (**implemented**; default
  256 MiB, t=3, p=4, ≈0.3 s per guess on the development machine — see `BENCHMARKS.md`).
* No decryption key is ever stored beside its ciphertext (**implemented**; contrast NoorSigner's
  trust mode in `RESEARCH.md`). The file contains no key bytes, hex, nsec, pubkey, label or
  password (**tested**: `vault_file_leaks_neither_secrets_nor_metadata`).
* Hostile or corrupted files cannot make us allocate unbounded memory/CPU before authentication
  (**tested**: `hostile_kdf_parameters_are_refused_before_any_work`, size cap, field-length checks).
* **Limit:** security equals password entropy. We enforce ≥ 10 characters but cannot make a bad
  password good. Old copies of the vault stay decryptable with the *old* password after a change
  (**documented & tested**); rotate the key (re-import to a new Nostr key) if an old copy leaked
  together with a weak password.
* **Limit:** an optional OS-keyring "device slot" (planned) trades this property for convenience: whoever
  can read that keyring entry can unlock the vault. It is off by default.

### A2 — other OS users (**mitigated by OS primitives**)
* Vault directory `0700`, files `0600`, atomic replace keeps them private (**tested on Unix**).
* Sockets: owner-only directory plus **peer-credential uid check** (`SO_PEERCRED` on Linux,
  `LOCAL_PEERCRED` on macOS) — *design, M3*. Windows: named pipe with a DACL granting only the
  current user's SID and `PIPE_REJECT_REMOTE_CLIENTS` — *design, M3*.

### A3 — buggy/over-eager apps (**primary design target of the local protocol**)
Requirements — **all implemented and tested in Milestone 3** except where noted:
* **Default deny.** An unpaired client can do nothing except pair; a paired client can do only what
  was granted: *account × client × operation × event kind × optional recipient × expiry/use limit*.
* **Decrypt ≠ sign.** `nip44_decrypt`/`nip04_decrypt` are separate operations with separate
  grants and stricter defaults; a signing grant never implies a decrypt grant
  (`Operation::reveals_plaintext` is already modelled in `embr-core`, **tested**).
* **What you approve is what is signed (TOCTOU).** The daemon stores a canonical copy of the
  request at submission time; the UI shows that copy; the signature is computed over that stored
  copy, never over anything re-read from the client. Approval messages reference the request id *and*
  a digest of the canonical request.
* **Confused deputy.** A request is bound to the (account, client) pair fixed at submission;
  switching the UI's "active account" never retargets a pending request, and a client can only name
  accounts it was granted. `pubkey` inside a template must equal the signing account
  (**implemented**: `PubkeyMismatch`, **tested**); client-supplied `id`/`sig` are never trusted
  (**implemented/tested**).
* **Resource exhaustion.** 1 MiB line limit, per-field limits (**implemented** in `embr-crypto::Limits`),
  per-client and global pending-queue caps, per-client rate limiting, handshake timeout, bounded
  buffers, request expiry (**implemented**; fuzzing is still M7).
* **Replay / substitution.** Per-connection server nonce in the authenticated hello; request ids are
  unique per session; responses are matched by id (M3).
* **Account switching.** Only the control channel (password-authenticated) can change the active
  account, and it never retargets a pending request (**implemented**).

### A4 — same-user malware (**the hard case — read carefully**)
A desktop OS gives every process of the same user broad powers. Embr **raises the bar** but cannot
make a single-user desktop safe against code that already runs as the user with full intent to
steal. Precisely:

**Embr *does* protect against (design targets, M3/M4):**
1. *Passive* theft: reading the vault, backups, logs, argv/environment, crash dumps without the
   password. Logs carry metadata only; secrets are passed on stdin/inherited fds, never argv
   (lesson from Omostrich); the daemon disables core dumps (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`).
2. Malware that **only speaks to the socket**: it is an *unpaired* client, so every request except
   "pair me" is refused and pairing needs a human approval that shows the client key fingerprint,
   the self-declared name flagged *unverified*, and peer hints (pid, exe path) flagged *untrusted*.
   It is rate-limited and cannot approve its own request: **approval is only accepted on the
   privileged control channel, which clients cannot use** (separate endpoint and credential from
   the client API).
3. A locked vault: no key material in memory; all operations return `vault_locked` (**implemented**
   at the library level, **tested**).
4. Blast radius: an approved app gets only the narrow, expiring grants it was given.

**Embr does *not* protect against, and says so:**
* Malware that can **read the daemon's memory** while the vault is unlocked (`ptrace`,
  `/proc/<pid>/mem`, `process_vm_readv`, Windows `ReadProcessMemory`). On Linux this depends on
  `kernel.yama.ptrace_scope` (1 on most distributions; **0 on some**, which allows it). We set the
  process non-dumpable, but a same-user process with debugger privileges can still win on weakly
  configured systems. Locking the vault promptly (auto-lock) shrinks the window.
* Malware that **steals an already-paired client's identity** (reads that client's private key
  file, or injects code into that client). It then holds exactly that client's grants — which is why
  grants are narrow and expiring, why "allow persistently" must be explicit, and why a "spawn-bound"
  mode (capability passed by an inherited descriptor, not a file) is offered for launchers
  (idea from Notary). A per-client *keypair proof-of-possession* stops secret-in-transit/log leaks
  and trivial name spoofing, **not** theft of the client's key file by same-user code.
* Malware that **drives the approval UI** (synthetic input on X11; accessibility APIs on some OSes)
  or **draws a fake prompt**. Wayland compositors block synthetic input by default; X11 does not.
  Mitigations are partial: the **anti-spoof word** (a per-session word known only to the daemon and
  UI) that was planned for M4 is **not implemented**; approvals are a click in the GUI (nothing proves
  the click was physical on X11); high-risk operations (decrypt, kinds 4/14/1059) can only be allowed
  once or for the session, or for at most an hour (decrypt).
* **Keyloggers / screen capture** that record the vault password or displayed plaintext.
* Any attacker who can modify the Embr binaries or the user's autostart entries. (Packages
  are signed where certificates exist; users on a compromised account lose.)

> **Bottom line for A4:** treat an unlocked Embr on a machine running hostile same-user code as
> compromised. Use auto-lock, keep the vault locked when idle, and don't run untrusted software as
> the same user — or run it in a sandbox (Flatpak, firejail, separate user) that cannot reach the
> socket.

### A5/A6 — NIP-46 (**implemented in Milestone 5**; off by default; tests listed in `SECURITY.md`)
* Nothing connects to a relay unless remote signing is **enabled by the user and configured**.
* Transport per NIP-46: kind `24133`, NIP-44 encryption, ephemeral/separate **signer keypair**
  (never the user key) so the signer's pubkey is not the user's pubkey (A5 cannot trivially correlate).
* `connect` secrets are single-use; `nostrconnect://` requires the client's `secret` in the reply;
  authorised client pubkeys are tracked per account with the same policy engine as local clients.
* Replay protection: reject events with a seen id, outside a freshness window, or from
  unauthorised pubkeys *before* any decryption work; bounded cache of seen ids.
* Relays are untrusted and may drop, reorder, replay or flood: timeouts, reconnection with backoff,
  per-client rate limits, no plaintext in logs.
* **Limit:** a relay learns *that* a signer and client talk (metadata), not what.

### A7 — malicious content in prompts (implemented in M3/M4; GUI shows the daemon-sanitised text)
* Event content and tags shown to the user are **rendered as inert text**: control and
  bidirectional-override characters are made visible, length is capped with an explicit "N more
  bytes" marker, URLs are not linkified, no markup/HTML is interpreted.
* Labels cannot contain controls or bidi overrides (**implemented/tested**) so a label cannot
  reorder text in the prompt around it.
* Events whose NIP-01 id would be verifier-dependent (C0 control characters) are refused
  (**implemented/tested**; `RESEARCH.md` F1).

### A8 — privileged attacker
Out of scope. Embr does not defend against root, a malicious kernel/hypervisor, DMA, or cold-boot
attacks and makes no claim to.

## 4. Process-identity limits per platform (what we can and cannot know about a caller)

| Platform | Mechanism | What it gives | Pitfalls |
|---|---|---|---|
| Linux | `SO_PEERCRED` (pid, uid, gid at connect time); `SO_PEERPIDFD` (kernel ≥ 6.5) | uid is reliable; pidfd ties to a live process | pid alone can be recycled between check and use; exe path (`/proc/pid/exe`) is a *hint*, a process can `exec` something else after connecting |
| macOS | `LOCAL_PEERCRED` (uid, gid), `LOCAL_PEERPID` | uid reliable | same pid/exe caveats; code-signature checks of the peer are possible but not planned |
| Windows | named-pipe DACL; `GetNamedPipeClientProcessId`; impersonation to learn the client SID | SID check; remote clients rejected by flag | pid reuse; elevated vs. non-elevated tokens; no portable "who is this app" |
| All | PID, process name, exe path, argv | **Display hints only.** Never an authentication factor. | Trivially spoofable by same-user code |

(These are properties of the OS documentation as I know them; each will be confirmed with a test
on the real platform in M3 and recorded in `TESTING.md`.)

## 5. Memory, swap, dumps, screen capture, compromised hosts

* **Zeroisation (implemented, best-effort):** secret keys (`nostr::SecretKey` erases on drop), the
  vault key, KEK, passwords, NIP-44/04 plaintexts and the decrypted vault body are held in
  zeroising containers and wiped on drop/lock. Rust gives **no** guarantee that *no other copy*
  exists: moves, reallocation inside third-party code, the Argon2 memory matrix (the crate's `zeroize` feature is enabled but not verified to wipe it all), `serde_json`
  internal buffers for non-secret metadata, and CPU registers/caches may leave residues.
* **Swap/hibernation:** not prevented. `mlock` of key pages (requires `unsafe`, confined to the
  future `embr-platform` crate) and encrypted swap are recommended; neither is implemented yet.
* **Core dumps:** the daemon will set `RLIMIT_CORE=0` and be non-dumpable; the systemd unit sets
  `LimitCORE=0` (M3/M6). Until then, a crash while unlocked on a system with `systemd-coredump`
  can write key material to disk — a finding Omostrich's author hit.
* **Screen capture / clipboard:** displayed plaintext and any copied `nsec` are exposed to anything
  that can capture them. Embr never puts a secret on the clipboard unprompted; reveal-nsec
  needs the vault password again (control API only; the GUI does not offer it).
* **Panics:** release builds use `panic = "abort"`, so a panic ends the process instead of unwinding
  through code that holds secrets; the vault's atomic writes mean a crash never corrupts it
  (**tested**: no temp files left, rollback on failed write).

## 6. Explicit non-goals
Protecting against a compromised OS; hiding that Embr is installed; defending against a user who
approves a malicious request after reading it (we make that harder to do by accident, not
impossible); multi-user separation inside one account; anonymity networks (Tor is not part of the
signer).
