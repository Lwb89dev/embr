# NIP-46 remote signing — plan

> **Status: not implemented (Milestone 5).** This page records requirements so the design is
> reviewable; it does not describe working software.

Requirements (from the brief and `RESEARCH.md`):
* Off by default; **no relay connection at start-up** unless remote signing is enabled and configured.
  Local signing never depends on it.
* Three distinct keys: the **user key** (in the vault), a **signer key** per account used only for transport
  (never the user key), and each **client key**.
* `bunker://` (signer-initiated, single-use `secret`) and `nostrconnect://` (client-initiated; the
  signer's `connect` reply must return the client's `secret`); QR display and URI import.
* Kind `24133`, NIP-44 transport encryption; methods: `connect` (incl. requested perms and client
  metadata), `get_public_key`, `sign_event`, `nip44_*`, `nip04_*`, `ping`, `switch_relays`; `auth_url`
  challenges where applicable.
* Same policy engine as local clients (per-client, per-kind, expiring grants).
* Replay protection (seen-id cache, freshness window, drop unauthorised pubkeys before decrypting),
  rate limits, request timeouts, reconnection with back-off, no plaintext in logs.
* Interop targets: `nak bunker` (different codebase/language), Amber, `nostr-connect` (rust-nostr),
  and a web client. Idea to evaluate: an optional **loopback-only** relay so same-machine NIP-46
  clients need no public relay (Amber Desktop does this).
* Not planned: a localhost HTTP service as a NIP-07 shortcut (rejected as an unauthenticated
  attack surface). An optional native-messaging NIP-07 bridge may follow later.
