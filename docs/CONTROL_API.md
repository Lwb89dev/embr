# Control channel API (GUI / CLI ↔ `embrd`)

> **Status: implemented in `embrd` (Unix), used by `embrctl`; the GUI will use it too.** This is a
> *privileged* interface: it is **not** for third-party applications (they use the client API in
> `LOCAL_SIGNER_API.md`). Types: `crates/embr-ipc/src/control.rs`. Client: `embr_client::control`.

* Separate socket `control.sock` (same directory rules and peer-uid check as `signer.sock`).
* Framing: JSON lines, 1 MiB limit; requests/responses as in the client API; strict parsing.
* **Authentication:** `unlock` / `create_vault` with the vault password returns a random `token`
  (store it in memory only). A reconnecting GUI sends `auth {token}`. Tokens and open authenticated
  connections die on every lock. Before authentication only `status`, `unlock`, `create_vault`,
  `auth` work. Wrong passwords are **throttled** (after 5 free attempts: exponential delay up to 5 min,
  even for the right password during the delay).
* **User activity** (any authenticated call except `status`, `list_pending`, `subscribe`) resets the idle
  auto-lock timer; traffic from signing clients does **not**.

| Method | Params | Result |
|---|---|---|
| `status` | – | version, vault state, pending count, lock timeout, remote-signing flag |
| `unlock`, `create_vault` | `{password}` | `{token}` |
| `auth` | `{token}` | `true` |
| `lock` | – | `true` (wipes keys, drops policy, cancels pending) |
| `change_password` | `{old,new}` | `true` (rotates the vault key) |
| `export_backup` | `{dest}` (absolute, must not exist) | `true` |
| `list_accounts` | – | `{accounts:[AccountMeta], active}` |
| `add_generated` / `import_secret` / `import_ncryptsec` | label (+ key / backup + password) | `AccountMeta` |
| `set_active` / `set_label` / `remove_account{confirm:true}` | account id … | `true` |
| `export_ncryptsec` / `reveal_nsec` | `{id, vault_password, …}` | `{ncryptsec}` / `{nsec}` — **step-up: vault password again** |
| `list_pending` | – | `[PendingView]` — the stored canonical request, sanitised |
| `decide` | `{id, digest, decision, scope?}` | the digest must match what the user reviewed |
| `subscribe` | – | then notifications: `pending_added`, `pending_removed`, `locked`, `unlocked`, `clients_changed`, `accounts_changed` |
| `list_clients`, `list_grants` | – | paired apps / stored permissions |
| `revoke_client`, `block_client`, `unblock_client`, `revoke_grant` | key / id | `true` |
| `get_settings`, `set_settings` | settings | lock timeout (0 or 30 s–24 h), notifications, remote signing (**off by default**) |
| `recent_log` | `{limit}` | metadata-only audit records |

Decisions: `allow_once`, `allow_session`, `allow_until{until}`, `allow_persistent`, `reject_once`,
`always_reject`, `pair{account}`, `block_client`. The policy engine may **refuse** a remembered choice
that is too broad (direct-message kinds, any-kind persistent, unscoped decrypt…); the request then
stays pending so the user can choose again. See `THREAT_MODEL.md` §A3.
