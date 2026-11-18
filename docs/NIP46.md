# NIP-46 remote signing

> **Status: implemented (Milestone 5), Linux/macOS, tested end to end** against an in-process relay and
> against an independent client (nostr-tools' `BunkerSigner`, JavaScript). `wss://` is tested over real TLS against
> an in-process relay with a throw-away certificate (including refusal of unknown-authority, wrong-name and
> expired certificates). Not yet tested against a second independent client (`nak`) or real public relays — see
> "Not verified". **Off by default.**

## What it is
Remote signing lets a NIP-46 client — a web app, a phone app, another machine — ask Embr to sign and
encrypt over Nostr relays, without ever holding a key. It complements the local protocol
(`LOCAL_SIGNER_API.md`); both go through **the same policy engine, approval queue and audit log**.

## Turning it on (opt-in, nothing connects before)
```bash
embrctl remote relays add wss://relay.example.com    # at least one relay (wss://, or ws:// to localhost)
embrctl remote enable
embrctl remote bunker main --qr                     # single-use bunker:// URI (+ QR) for the account "main"
embrctl watch                                       # approve the app when it connects
```
* The relay service exists only while **remote signing is enabled AND the vault is unlocked AND a relay
  is configured**. Otherwise the process opens no network connection (tested: a relay sees zero
  connections with defaults, with "enabled but no relays", after disabling, and after a lock).
* Locking the vault stops accepting remote requests at once, answers requests already in flight with an
  error, then disconnects from every relay (≈0.75 s). Unlocking restores the service (the settings and
  pairings live in the encrypted vault).
* **systemd:** the shipped sandbox allows `AF_UNIX` only, so with remote signing enabled the relay shows
  `failed (Address family not supported…)`. Install the drop-in
  `packaging/systemd/embrd-remote.conf` (also in `/usr/share/doc/embr/examples/` of the Arch package) to allow
  network sockets. Verified both ways on 2026-11-17.

## Keys: user key, signer (transport) key, client key
* **User key** — in the vault; never leaves it.
* **Signer / transport key** — one random key pair **per account**, generated on first use and stored in
  the vault (`nip46/v1` blob). It is the pubkey in `bunker://…`, it signs NIP-46 responses and NIP-42
  `AUTH` events, and it decrypts requests. It is **never** the user key, so a relay or a client learns
  nothing about the user's identity from the signer's pubkey until `get_public_key` is answered.
* **Client key** — the app's key; its identity in the policy engine (`via = "nip46"`).
* The transport key a request is addressed to **selects the account**. A client paired to account A that
  addresses account B's transport key is refused (tested).

## Flows
**`bunker://` (signer-initiated)** — `embrctl remote bunker <account>` creates
`bunker://<transport-pubkey>?relay=…&secret=<random>`; the user pastes it into the app. The secret is
**single-use, valid 10 minutes, kept only in memory (hashed)**. The app sends `connect [signer, secret, perms?,
metadata?]`. A valid secret only brings the app *to the approval prompt* (which shows its key, its
self-declared name/URL — flagged unverified — and the permissions it asked for, as a wish); the user still
approves. A wrong, reused or missing secret gets an error and **no prompt**.

**`nostrconnect://` (client-initiated)** — the app shows a `nostrconnect://<client-pubkey>?relay=…&secret=…`
URI; the user imports it with `embrctl remote connect <uri> --account <id>` (a GUI would scan the QR).
The prompt lists the relays; **those relays are contacted only after approval**, then Embr sends the
`connect` response carrying the client's `secret` (as NIP-46 requires) and serves the client on them.
A rejected URI never causes a connection (tested).

After pairing, requests are authorised exactly like local ones: nothing is signed or decrypted without a
matching permission or an approval; decrypt is a separate, stricter grant; direct-message kinds cannot be
remembered; *always reject* and revocation work the same way.

## Methods
`connect`, `get_public_key`, `sign_event`, `nip44_encrypt`, `nip44_decrypt`, `nip04_encrypt`,
`nip04_decrypt` (**legacy**, flagged), `ping`, `switch_relays` (returns the configured relays).
Anything else: error. Transport encryption is **NIP-44 only** (kind `24133`); clients that still wrap NIP-46
in NIP-04 are not supported.

## Defences (all tested)
Applied in this order, before a request can reach the policy engine:
1. kind 24133, exactly one `p` tag naming one of our transport keys, valid event id and signature;
2. freshness: `created_at` within ±10 minutes (a hostile relay can replay old events);
3. replay: each event id is processed once (8 192-entry cache);
4. **per-client rate limit before any ECDH/decryption** (token bucket; one client's flood does not starve another);
5. strict JSON-RPC parsing (`deny_unknown_fields`, string params, id/param limits);
6. bounded concurrency; unknown clients can only `connect` (and `ping`).
Relays are untrusted: inbound messages ≤ 1 MiB; reconnection with exponential backoff (1 s → 60 s);
keep-alive ping every 30 s and a 90 s dead-connection timeout; NIP-42 `AUTH` answered with the *transport* key;
relay URLs must be `wss://` (or `ws://` to loopback), with no credentials, fragments or control characters
(**a fuzzer found a flaw here, now fixed** — see `SECURITY.md`).

## Interoperability
`apps/embrd/tests/nip46_interop.rs` runs nostr-tools' `BunkerSigner` as the client: connect with metadata,
`get_public_key` (gets the *user* pubkey), `sign_event` (signature verifies in nostr-tools), `nip44_encrypt`
(decrypts in nostr-tools), `ping` — via `bunker://` **and** via `nostrconnect://` (`fromURI`). Both pass.
Run with `tests/interop/run.sh`.

## Not implemented / not verified
* `auth_url` challenges (we never need the user to visit a URL), NIP-89 discovery, `get_relays`, `logout`.
* A **loopback-only relay inside the daemon** (Amber Desktop has one) — an idea for later.
* TLS (`wss://`) is rustls + ring + bundled Mozilla roots (ADR-9). Exercised against an in-process TLS relay
  (`crates/embr-nip46/tests/tls.rs`), **not** yet against a real public relay with a CA-signed certificate.
  Certificate pinning is not implemented.
* Interop with other NIP-46 *clients* besides nostr-tools (e.g. `nak`); behaviour on flaky mobile networks; many
  relays. (Amber is not a counterpart for this test: it is another *signer*, so Embr cannot be exercised through it.)
* Tor/onion relays; per-relay settings; relay metadata leaks (a relay learns *that* a signer and client
  talk, not what).
* Windows (no daemon transport yet).
