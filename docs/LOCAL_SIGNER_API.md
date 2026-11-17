# Embr Local Signer API — protocol draft v1

> **Status: protocol v1 — implemented in `embrd` on Linux/macOS (Unix sockets), tested on Linux.**
> Windows (named pipes) and spawn-bound clients are **not implemented yet**. The wire format may
> still change before `1.0`. Reference implementation: `crates/embr-ipc` (types, framing, proof),
> `apps/embrd` (server), `crates/embr-client` (blocking Rust SDK; example in
> `crates/embr-client/examples/login_and_sign.rs`). The privileged channel used by the GUI/CLI is a
> different socket, described in `CONTROL_API.md`.
>
> *Differences between the original draft and the implementation:* `list_accounts` also returns
> `npub`; error code 14 `busy` was added; the `account` selector of an **unpaired** client is
> ignored (the user chooses the account, and the client learns nothing about the vault); a paired
> client calling `connect` again gets its pairing back without a prompt.
>
> This is **not NIP-55** (an Android-only intent/ContentProvider protocol) and **not NIP-46**
> (relay-based remote signing). It is a desktop-local protocol; its framing and method names are
> intentionally close to Amber Desktop's local socket (a draft "NIP-5F") and to NIP-46, but its
> authentication is different (see §4).

## 1. Goals and non-goals
* Let a native app on the **same machine** get a public key, signatures and NIP-44/NIP-04 operations
  **without ever seeing a private key**, with no relay and no network.
* Strong default: **an unknown client can do nothing** until the user pairs it.
* Easy to implement in any language: line-delimited JSON, one socket, one handshake.
* Non-goal: protecting a client's own credentials from malware running as the same user
  (see `THREAT_MODEL.md` §A4).

## 2. Transport and discovery

| OS | Endpoint | Protection |
|---|---|---|
| Linux | `$XDG_RUNTIME_DIR/embr/signer.sock` (fallback `$TMPDIR/embr-<uid>/signer.sock`) | directory `0700`, socket `0600`, **peer uid must equal daemon uid** (`SO_PEERCRED`) |
| macOS | `$TMPDIR/embr-<uid>/signer.sock` | same, `LOCAL_PEERCRED` |
| Windows | `\\.\pipe\embr-signer-<sid-hash>` | DACL = current user SID only, `PIPE_REJECT_REMOTE_CLIENTS` |

* Override with the `EMBR_SIGNER_SOCKET` environment variable (path or pipe name).
* **Discovery** = try to connect. A refused/missing endpoint means "signer not running"; the client
  may start it (`embrd`, user-level) and retry. Clients MUST NOT scan or probe other paths.
* The control channel used by the GUI is a *different* endpoint and is not part of this API.

## 3. Framing
UTF-8 JSON, **one object per line** terminated by `\n`, at most **1 048 576 bytes** per line.
A longer line, invalid UTF-8, a NUL byte or non-JSON closes the connection after a structured
error `payload_too_large` / `invalid_request` where possible. Requests may overlap; answers are
matched by `id`, not by order.

## 4. Handshake and client authentication

A client has a long-lived **client key**: an ordinary secp256k1/BIP-340 key pair that it generates
and stores itself (no new cryptography; the same key format Nostr clients already handle).

```
S → C  {"embr":1,"name":"Embr","version":"0.1.0","protocol":[1],
        "methods":["get_public_key","sign_event",…],"nonce":"<64 hex, fresh per connection>"}
C → S  {"hello":{"protocol":1,
                 "client":{"name":"OUTKAST","pubkey":"<64 hex>"},
                 "proof":"<128 hex BIP-340 signature>"}}
S → C  {"ok":true,"session":"<opaque id>","paired":false}      // or {"ok":false,"error":{…}}
```

`proof` = `schnorr_sign(client_secret, sha256("embr-local/1\0" || nonce || client_pubkey))`.

* The server nonce is fresh per connection, so a `hello` captured elsewhere cannot be replayed.
* `client.name` is a **self-declared label**. It is shown to the user as *unverified*; identity is the
  **public key**. Two clients with the same name but different keys are different clients.
* A bad proof ⇒ `unauthenticated` and the connection is closed. A client that sends no `hello`
  within 5 s is disconnected.
* The server additionally records peer credentials (pid, uid, exe path where available). They are
  **display hints for the approval prompt, never part of authentication.**
* **Spawn-bound clients (optional, planned):** a launcher may start a child with a pre-connected
  socketpair descriptor; holding that descriptor *is* the credential, and no key file exists.

## 5. Requests and responses

```jsonc
// request
{"id":"7","method":"sign_event","params":{"account":"<hex or npub, optional>","event":{…}},
 "timeout_ms":60000}
// success
{"id":"7","result":{…},"error":null}
// failure
{"id":"7","result":null,"error":{"code":5,"name":"denied","message":"user rejected"}}
```

* `id`: string (≤ 64 chars), unique within a session; a duplicate is rejected (`invalid_request`).
* `timeout_ms`: optional; the server caps it (default 120 000, max 600 000). On expiry the pending
  request is removed and answered `expired` — never left hanging.
* `cancel`: `{"method":"cancel","params":{"id":"7"}}` withdraws a pending request (answered
  `cancelled`).
* Strict parsing: unknown top-level or `params` fields are errors.

### Methods

| Method | `params` | `result` | Notes |
|---|---|---|---|
| `connect` | `{"permissions":["sign_event:1","nip44_encrypt"], "label":"…"}` | `{"paired":true,"account":"<hex pubkey>"}` | Starts pairing; the user chooses account and grants. `permissions` is a *request*, never a grant. |
| `get_public_key` | `{"account"?}` | hex pubkey | Unpaired client ⇒ equivalent to `connect` with no permissions (login flow à la NIP-55). |
| `list_accounts` | `{}` | `[{"pubkey","label"}]` | Only accounts this client is granted. |
| `sign_event` | `{"account"?,"event":{kind,content,tags,created_at?}}` | signed event object | `pubkey`/`id` if present must match; `sig` rejected (`embr-crypto`). |
| `nip44_encrypt` | `{"account"?,"peer":"<hex|npub>","plaintext"}` | payload string | Preferred encryption. |
| `nip44_decrypt` | `{"account"?,"peer","payload"}` | plaintext | **Separate grant**; returns private data to the caller. |
| `nip04_encrypt` / `nip04_decrypt` | as above | | **Legacy**; shown as such; separate grants. |
| `ping` | `{}` | `"pong"` | Allowed unpaired after a valid `hello`. |
| `revoke_self` | `{}` | `true` | Client forgets its own pairing. |

Requests from an unpaired client other than `connect`/`get_public_key`/`ping` fail with `not_paired`.

### Errors

| Code | `name` | Meaning |
|---:|---|---|
| 1 | `invalid_request` | not JSON/shape, duplicate id, unknown field |
| 2 | `unsupported_method` | includes anything not in the table |
| 3 | `invalid_params` | bad event/template, bad key, limit exceeded |
| 4 | `account_not_found` | unknown or not granted to this client |
| 5 | `denied` | user rejected, or stored *always reject* |
| 6 | `vault_locked` | answered immediately while locked |
| 7 | `expired` | pending request timed out |
| 8 | `cancelled` | client cancelled / disconnected / account removed |
| 9 | `rate_limited` | `data.retry_after_ms` present |
| 10 | `internal` | |
| 11 | `payload_too_large` | |
| 12 | `unauthenticated` | missing/invalid `hello` proof |
| 13 | `not_paired` | client key unknown to the daemon |

(Codes 1–5 and 10 mirror Amber Desktop's published table for easy adaptation.)

## 6. Authorisation semantics (summary; engine in `embr-policy`)

Decisions: *allow once · allow for this session · allow until \<time> · allow persistently
(narrow scope only) · reject once · always reject · revoke.* Scope = **account × client key ×
operation × event kind × optional peer/recipient × expiry/use-count**. Rules the daemon enforces:

1. Default deny; no unrestricted automatic signing for a newly paired client.
2. A decrypt grant never implies sign, nor vice versa. Kinds `4`, `14`, `1059` (DMs/gift wraps)
   cannot be remembered as blanket grants.
3. The request shown to the user is the stored canonical copy; the signature is computed over it.
4. A request is bound to its (account, client) at submission; UI account switching does not
   retarget it.
5. A locked vault answers `vault_locked` at once; a lock event resolves all pending requests with
   `cancelled`.

## 7. Abuse resistance (defaults; configurable)

| Limit | Default |
|---|---|
| Line size | 1 MiB |
| Concurrent unauthenticated connections | 8 |
| Handshake deadline | 5 s |
| Pending requests per client / total | 16 / 64 |
| Requests per client | 20 burst, 5 /s sustained (token bucket) |
| Idle session | 15 min |

## 8. Writing a client (sketch)
1. Load or create your client key (store it `0600`, in your app's config dir).
2. Connect; read the handshake; sign the proof; send `hello`.
3. `connect` (or `get_public_key`) — the user approves in Embr.
4. Call methods; match responses by `id`; handle `vault_locked`, `denied`, `expired`.
5. Never log the client secret, plaintexts or signatures you did not ask for.

The Rust SDK (`embr-client`) does steps 1–4 for you; see
`crates/embr-client/examples/login_and_sign.rs` for a complete app. For other languages implement the
handshake yourself: it needs only line-delimited JSON over a Unix socket and one BIP-340 signature
(use any Nostr library to sign the proof *event* of kind `27183` with tags
`["embr_nonce", <nonce>]` and `["embr_proto","1"]`, empty content, current `created_at`).
A Python and a shell walkthrough are still to be written.

## 9. Open questions (feedback welcome)
* Provide a compatibility mode that accepts the NIP-5F-draft hello (`{"client":"nak"}`) as an
  *unpaired* client so that tools like `nak` can pair? (Probably yes, with pairing mandatory.)
* NIP-44 "v3"-style context parameters (Amber): not in the NIPs at the examined commit; not planned.
* Per-request user-presence proof (e.g. polkit/biometric) for the highest-risk operations.
