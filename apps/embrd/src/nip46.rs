//! NIP-46 remote signing inside the daemon.
//!
//! The relay service ([`embr_nip46::service::Service`]) exists **only while** all of these hold:
//! the vault is unlocked, remote signing is enabled in the settings, and at least one relay is
//! configured. Otherwise this process opens no network connection at all.
//!
//! Remote requests go through the very same [`submit`](crate::client_api::submit) as local ones:
//! one policy engine, one approval queue, one audit log. NIP-46 specifics handled here:
//!
//! * **Transport keys**: one random key pair per account, stored inside the encrypted vault
//!   (`nip46/v1` blob). The `bunker://` pubkey is the transport key, never the user's key, and the
//!   transport key addressed by a request selects the account — a client paired to account A that
//!   addresses account B's transport key is refused.
//! * **`bunker://` secrets**: random, single-use, valid 10 minutes, kept in memory only (hashed).
//!   A valid secret only gets the client *to the approval prompt*; the user still approves it.
//! * **`nostrconnect://`**: the user imports the URI and picks the account; the prompt shows the
//!   client's key, name and relays; relays of a URI are contacted **only after approval**.
//! * Unpaired clients can only `connect` (and `ping`); anything else is refused.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, Weak};
use std::time::{Duration, Instant};

use embr_core::display::sanitize;
use embr_core::{AccountId, Pubkey32};
use embr_crypto::Identity;
use embr_ipc::control::{Nip46Status, RelayView, SignerView, VaultState};
use embr_ipc::{ErrorCode, Request, RpcError};
use embr_nip46::relay::RelayState;
use embr_nip46::service::{Call, CallFuture, Handler, Service, ServiceConfig};
use embr_nip46::uri::{BunkerUri, NostrConnectUri, validate_relay};
use embr_policy::SessionId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::canonical::Canonical;
use crate::client_api::{Origin, Submitted, enqueue, wait_submitted};
use crate::state::{Inner, NostrConnectCtx, PendingExtra, ReplyKind, Shared};

/// Name of the blob holding transport keys and per-client relays.
pub const NIP46_BLOB: &str = "nip46/v1";
/// Lifetime of a `bunker://` connection secret.
pub const SECRET_TTL: Duration = Duration::from_secs(600);
const MAX_SECRETS: usize = 16;

struct BunkerSecret {
    hash: [u8; 32],
    account: AccountId,
    expires: Instant,
}

/// Everything NIP-46 needs from the unlocked state.
#[derive(Default)]
pub struct Nip46State {
    /// Transport secret keys per account.
    pub keys: BTreeMap<AccountId, Zeroizing<[u8; 32]>>,
    /// Transport public key → account.
    pub signer_account: BTreeMap<Pubkey32, AccountId>,
    /// Relays announced by paired `nostrconnect://` clients (contacted only after approval).
    pub client_relays: BTreeMap<Pubkey32, Vec<String>>,
    secrets: Vec<BunkerSecret>,
    sessions: BTreeMap<Pubkey32, SessionId>,
    known_signers: Vec<Pubkey32>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Stored {
    #[serde(default)]
    keys: BTreeMap<String, String>,
    #[serde(default)]
    client_relays: BTreeMap<String, Vec<String>>,
}

impl Nip46State {
    /// Loads the stored blob (ignoring anything malformed rather than refusing to unlock).
    pub fn load(blob: Option<Vec<u8>>) -> Self {
        let mut st = Nip46State::default();
        let Some(mut bytes) = blob else { return st };
        if let Ok(stored) = serde_json::from_slice::<Stored>(&bytes) {
            for (acct, hexsk) in stored.keys {
                let (Ok(acct), Ok(raw)) = (acct.parse::<AccountId>(), hex::decode(&hexsk)) else {
                    continue;
                };
                let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) else {
                    continue;
                };
                let arr = Zeroizing::new(arr);
                if let Ok(id) = Identity::from_secret_bytes(&arr) {
                    if let Ok(pk) = id.pubkey_hex().parse::<Pubkey32>() {
                        st.signer_account.insert(pk, acct);
                        st.keys.insert(acct, arr);
                    }
                }
            }
            for (client, relays) in stored.client_relays {
                let valid: Vec<String> = relays
                    .iter()
                    .filter_map(|r| validate_relay(r).ok())
                    .collect();
                if let (Ok(c), false) = (client.parse::<Pubkey32>(), valid.is_empty()) {
                    st.client_relays.insert(c, valid);
                }
            }
        }
        zeroize::Zeroize::zeroize(&mut bytes);
        st
    }

    fn to_blob(&self) -> Zeroizing<Vec<u8>> {
        let stored = Stored {
            keys: self
                .keys
                .iter()
                .map(|(a, k)| (a.to_string(), hex::encode(**k)))
                .collect(),
            client_relays: self
                .client_relays
                .iter()
                .map(|(c, r)| (c.to_string(), r.clone()))
                .collect(),
        };
        Zeroizing::new(serde_json::to_vec(&stored).unwrap_or_default())
    }

    /// The transport public key of `account`, creating the key if needed. Returns whether it was new.
    pub fn ensure_key(&mut self, account: AccountId) -> Result<(Pubkey32, bool), RpcError> {
        if let Some(sk) = self.keys.get(&account) {
            let pk = pubkey_of(sk)?;
            return Ok((pk, false));
        }
        let id = Identity::generate();
        let sk = id.secret_bytes();
        let pk = id
            .pubkey_hex()
            .parse::<Pubkey32>()
            .map_err(|_| RpcError::new(ErrorCode::Internal, "key error"))?;
        self.signer_account.insert(pk, account);
        self.keys.insert(account, Zeroizing::new(*sk));
        Ok((pk, true))
    }

    /// Forgets everything about an account.
    pub fn remove_account(&mut self, account: AccountId) {
        self.keys.remove(&account);
        self.signer_account.retain(|_, a| *a != account);
        self.secrets.retain(|s| s.account != account);
    }
}

fn pubkey_of(sk: &Zeroizing<[u8; 32]>) -> Result<Pubkey32, RpcError> {
    Identity::from_secret_bytes(sk)
        .ok()
        .and_then(|i| i.pubkey_hex().parse().ok())
        .ok_or_else(|| RpcError::new(ErrorCode::Internal, "key error"))
}

fn rpc(code: ErrorCode, msg: &str) -> RpcError {
    RpcError::new(code, msg)
}

/// Persists the NIP-46 blob.
pub fn persist(g: &mut Inner) -> Result<(), RpcError> {
    let blob = g.nip46.to_blob();
    g.vault_mut()?
        .set_blob(NIP46_BLOB, Some(&blob))
        .map_err(crate::state::map_vault_err)
}

/// Starts, updates or stops the relay service to match the current state. Idempotent. Must be
/// called from within the tokio runtime.
pub fn sync(shared: &Arc<Shared>) {
    let (want, relays, signers) = {
        let g = shared.lock();
        let want = g.vault_state() == VaultState::Unlocked
            && g.settings.remote_signing_enabled
            && !g.settings.relays.is_empty();
        let mut relays: Vec<String> = g
            .settings
            .relays
            .iter()
            .filter_map(|r| validate_relay(r).ok())
            .collect();
        for r in g.nip46.client_relays.values().flatten() {
            if !relays.contains(r) {
                relays.push(r.clone());
            }
        }
        relays.truncate(32);
        let signers: Vec<(Pubkey32, Zeroizing<[u8; 32]>)> = g
            .nip46
            .keys
            .values()
            .filter_map(|sk| pubkey_of(sk).ok().map(|pk| (pk, sk.clone())))
            .collect();
        (want, relays, signers)
    };
    let mut slot = shared
        .nip46_service
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if !want {
        if let Some(svc) = slot.take() {
            svc.stop();
        }
        return;
    }
    let l = &shared.cfg.limits;
    let svc = slot
        .get_or_insert_with(|| {
            Service::start(
                Arc::new(DaemonHandler(Arc::downgrade(shared))),
                ServiceConfig {
                    rate_burst: l.rate_burst,
                    rate_per_sec: l.rate_per_sec,
                    ..ServiceConfig::default()
                },
                &shared.shutdown,
            )
        })
        .clone();
    drop(slot);

    let keep: Vec<Pubkey32> = signers.iter().map(|(pk, _)| *pk).collect();
    let stale: Vec<Pubkey32> = {
        let g = shared.lock();
        g.nip46
            .known_signers
            .iter()
            .filter(|k| !keep.contains(k))
            .copied()
            .collect()
    };
    for pk in &stale {
        svc.remove_signer(pk);
    }
    for (_, sk) in &signers {
        if let Ok(id) = Identity::from_secret_bytes(sk) {
            svc.add_signer(id);
        }
    }
    shared.lock().nip46.known_signers = keep;
    svc.set_relays(&relays);
}

/// `nip46_status`.
pub fn status(shared: &Arc<Shared>) -> Nip46Status {
    let svc = shared
        .nip46_service
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let g = shared.lock();
    let relays = svc
        .map(|s| {
            s.status()
                .into_iter()
                .map(|r| match r.state {
                    RelayState::Connecting => RelayView {
                        url: r.url,
                        state: "connecting".into(),
                        detail: None,
                    },
                    RelayState::Connected => RelayView {
                        url: r.url,
                        state: "connected".into(),
                        detail: None,
                    },
                    RelayState::Failed(why) => RelayView {
                        url: r.url,
                        state: "failed".into(),
                        detail: Some(why),
                    },
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Nip46Status {
        enabled: g.settings.remote_signing_enabled,
        running: !relays.is_empty()
            || shared
                .nip46_service
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some(),
        relays,
        signers: g
            .nip46
            .signer_account
            .iter()
            .map(|(pk, a)| SignerView {
                account: *a,
                transport_pubkey: *pk,
            })
            .collect(),
    }
}

/// `nip46_bunker`: creates a single-use `bunker://` URI for `account`.
pub fn create_bunker(shared: &Arc<Shared>, account: AccountId) -> Result<Value, RpcError> {
    let mut g = shared.lock();
    g.vault_ref()?;
    if !g.settings.remote_signing_enabled || g.settings.relays.is_empty() {
        return Err(rpc(
            ErrorCode::InvalidRequest,
            "enable remote signing and configure at least one relay first (settings)",
        ));
    }
    if !g.accounts()?.iter().any(|a| a.id == account) {
        return Err(rpc(ErrorCode::AccountNotFound, "no such account"));
    }
    let (signer, created) = g.nip46.ensure_key(account)?;
    if created {
        persist(&mut g)?;
    }
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| rpc(ErrorCode::Internal, "rng failure"))?;
    let secret = hex::encode(raw);
    g.nip46.secrets.retain(|s| s.expires > Instant::now());
    if g.nip46.secrets.len() >= MAX_SECRETS {
        g.nip46.secrets.remove(0);
    }
    g.nip46.secrets.push(BunkerSecret {
        hash: Sha256::digest(secret.as_bytes()).into(),
        account,
        expires: Instant::now() + SECRET_TTL,
    });
    let relays = g.settings.relays.clone();
    g.audit_admin("nip46_bunker", None);
    drop(g);
    sync(shared);
    let uri = BunkerUri {
        signer,
        relays,
        secret: Some(secret),
    }
    .render();
    Ok(
        json!({"uri": uri, "transport_pubkey": signer.to_string(), "expires_in_secs": SECRET_TTL.as_secs()}),
    )
}

/// `nip46_connect`: imports a client-created `nostrconnect://` URI and asks the user to approve it.
pub async fn import_nostrconnect(
    shared: &Arc<Shared>,
    uri: &str,
    account: AccountId,
) -> Result<Value, RpcError> {
    let nc =
        NostrConnectUri::parse(uri).map_err(|e| rpc(ErrorCode::InvalidParams, &e.to_string()))?;
    let (origin, id, rx, timeout, signer) = {
        let mut g = shared.lock();
        g.vault_ref()?;
        if !g.settings.remote_signing_enabled {
            return Err(rpc(
                ErrorCode::InvalidRequest,
                "enable remote signing first (settings)",
            ));
        }
        let meta = g
            .accounts()?
            .into_iter()
            .find(|a| a.id == account)
            .ok_or_else(|| rpc(ErrorCode::AccountNotFound, "no such account"))?;
        if g.policy.is_blocked(&nc.client) {
            return Err(rpc(ErrorCode::Denied, "this client key is blocked"));
        }
        let (signer, created) = g.nip46.ensure_key(account)?;
        if created {
            persist(&mut g)?;
        }
        let name = sanitize(
            nc.name.as_deref().unwrap_or("nostrconnect client").trim(),
            64,
        );
        let origin = nip46_origin(shared, &mut g, nc.client, &name);
        let perms: Vec<String> = nc.perms.iter().take(32).map(|p| sanitize(p, 64)).collect();
        let text = format!(
            "relays (contacted only if you approve): {}{}",
            nc.relays.join(", "),
            nc.url
                .as_deref()
                .map(|u| format!(" · app url: {}", sanitize(u, 120)))
                .unwrap_or_default()
        );
        let timeout = Duration::from_millis(shared.cfg.limits.default_timeout_ms);
        let (id, rx) = enqueue(
            shared,
            &mut g,
            &origin,
            Canonical::Pair {
                name,
                permissions: perms,
            },
            Some(meta),
            None,
            ReplyKind::Connect,
            timeout,
            PendingExtra {
                text: Some(text),
                fixed_account: Some(account),
                nostrconnect: Some(NostrConnectCtx {
                    signer,
                    secret: nc.secret.clone(),
                    relays: nc.relays.clone(),
                }),
            },
        )?;
        (origin, id, rx, timeout, signer)
    };
    let sh = shared.clone();
    let client = nc.client;
    let secret = nc.secret.clone();
    tokio::spawn(async move {
        let done = wait_submitted(
            &sh,
            Submitted::Wait { id, rx, timeout },
            sh.shutdown.child_token(),
        )
        .await;
        let payload = match done {
            Ok(_) => json!({"id": new_rpc_id(), "result": secret}),
            Err(e) => json!({"id": new_rpc_id(), "error": e.message}),
        };
        // The approval added the client's relays and (re)started the pool; give it a moment to connect.
        let svc = sh
            .nip46_service
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(svc) = svc {
            for attempt in 0..4 {
                if svc.send(&signer, &client, &payload.to_string()).await > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1 + attempt)).await;
            }
        }
    });
    drop(origin);
    Ok(json!({"pending_id": id}))
}

fn new_rpc_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

fn nip46_origin(shared: &Shared, g: &mut Inner, client: Pubkey32, name: &str) -> Origin {
    let session = *g
        .nip46
        .sessions
        .entry(client)
        .or_insert_with(|| shared.new_session());
    let known = g.policy.client(&client).map(|c| c.name.clone());
    Origin {
        session,
        client,
        client_name: known.unwrap_or_else(|| name.to_owned()),
        peer: None,
        via: "nip46",
    }
}

// ===== the call handler ================================================================

struct DaemonHandler(Weak<Shared>);

impl Handler for DaemonHandler {
    fn call(&self, call: Call) -> CallFuture {
        let weak = self.0.clone();
        Box::pin(async move {
            let Some(shared) = weak.upgrade() else {
                return Err("the signer is shutting down".into());
            };
            handle_call(&shared, call).await.map_err(|e| e.message)
        })
    }
}

fn param(call: &Call, i: usize) -> Result<&str, RpcError> {
    call.params
        .get(i)
        .map(String::as_str)
        .ok_or_else(|| rpc(ErrorCode::InvalidParams, "missing parameter"))
}

async fn handle_call(shared: &Arc<Shared>, call: Call) -> Result<String, RpcError> {
    if call.method == "ping" {
        return Ok("pong".into());
    }
    let account = {
        let g = shared.lock();
        g.vault_ref()?;
        *g.nip46
            .signer_account
            .get(&call.signer)
            .ok_or_else(|| rpc(ErrorCode::AccountNotFound, "unknown signer key"))?
    };
    if call.method == "connect" {
        return handle_connect(shared, &call, account).await;
    }

    // Everything else requires a client that is already paired to *this* transport key's account.
    let (origin, account_pubkey) = {
        let mut g = shared.lock();
        let rec = g.policy.client(&call.client).cloned();
        match &rec {
            Some(r) if r.accounts.contains(&account) => {}
            Some(_) => {
                return Err(rpc(
                    ErrorCode::AccountNotFound,
                    "this client is not paired to that signer key",
                ));
            }
            None => {
                return Err(rpc(
                    ErrorCode::NotPaired,
                    "not connected: send `connect` first",
                ));
            }
        }
        let meta = g
            .accounts()?
            .into_iter()
            .find(|a| a.id == account)
            .ok_or_else(|| rpc(ErrorCode::AccountNotFound, "account not found"))?;
        let name = rec.map(|r| r.name).unwrap_or_default();
        (
            nip46_origin(shared, &mut g, call.client, &name),
            meta.pubkey_hex,
        )
    };
    let (method, params): (&str, Value) = match call.method.as_str() {
        "get_public_key" => ("get_public_key", json!({"account": account_pubkey})),
        "sign_event" => {
            let event: Value = serde_json::from_str(param(&call, 0)?).map_err(|_| {
                rpc(
                    ErrorCode::InvalidParams,
                    "the event parameter must be a JSON string",
                )
            })?;
            (
                "sign_event",
                json!({"account": account_pubkey, "event": event}),
            )
        }
        m @ ("nip44_encrypt" | "nip04_encrypt") => (
            m,
            json!({"account": account_pubkey, "peer": param(&call, 0)?, "plaintext": param(&call, 1)?}),
        ),
        m @ ("nip44_decrypt" | "nip04_decrypt") => (
            m,
            json!({"account": account_pubkey, "peer": param(&call, 0)?, "payload": param(&call, 1)?}),
        ),
        "switch_relays" => {
            let g = shared.lock();
            let relays: Vec<&String> = g.settings.relays.iter().collect();
            return Ok(serde_json::to_string(&relays).unwrap_or_else(|_| "[]".into()));
        }
        other => {
            return Err(rpc(
                ErrorCode::UnsupportedMethod,
                &format!("unsupported method {other}"),
            ));
        }
    };
    let req = Request {
        id: call.id.clone(),
        method: method.to_owned(),
        params,
        timeout_ms: None,
    };
    let submitted = crate::client_api::submit(shared, &origin, &req);
    let done = wait_submitted(shared, submitted, shared.shutdown.child_token()).await?;
    Ok(match done {
        Value::String(s) => s,
        other => other.to_string(), // sign_event → the signed event as a JSON string
    })
}

async fn handle_connect(
    shared: &Arc<Shared>,
    call: &Call,
    account: AccountId,
) -> Result<String, RpcError> {
    if param(call, 0)? != call.signer.to_string() {
        return Err(rpc(
            ErrorCode::InvalidParams,
            "the first parameter must be the signer public key",
        ));
    }
    let secret = call.params.get(1).filter(|s| !s.is_empty());
    let perms: Vec<String> = call
        .params
        .get(2)
        .map(|p| {
            p.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .take(32)
                .map(|x| sanitize(x, 64))
                .collect()
        })
        .unwrap_or_default();
    let meta: Option<Value> = call
        .params
        .get(3)
        .and_then(|m| serde_json::from_str(m).ok());
    let label = meta
        .as_ref()
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .map_or_else(|| "NIP-46 client".to_owned(), |n| sanitize(n.trim(), 64));
    let app_url = meta
        .as_ref()
        .and_then(|m| m.get("url"))
        .and_then(Value::as_str)
        .map(|u| sanitize(u, 120));

    let (origin, id, rx, timeout) = {
        let mut g = shared.lock();
        g.vault_ref()?;
        if g.policy.is_blocked(&call.client) {
            return Err(rpc(ErrorCode::Denied, "this client is blocked"));
        }
        // Already paired to this account: just acknowledge.
        if g.policy
            .client(&call.client)
            .is_some_and(|c| c.accounts.contains(&account))
        {
            return Ok("ack".into());
        }
        // Otherwise a valid single-use secret is required to even reach the approval prompt.
        let given = secret.map(|s| -> [u8; 32] { Sha256::digest(s.as_bytes()).into() });
        let now = Instant::now();
        g.nip46.secrets.retain(|s| s.expires > now);
        let pos = given.and_then(|h| {
            g.nip46
                .secrets
                .iter()
                .position(|s| s.hash == h && s.account == account)
        });
        let Some(pos) = pos else {
            g.audit_admin(
                "nip46_connect_refused",
                Some("invalid or expired connection secret"),
            );
            return Err(rpc(
                ErrorCode::Denied,
                "invalid or expired connection secret",
            ));
        };
        g.nip46.secrets.remove(pos); // single use
        let meta = g.accounts()?.into_iter().find(|a| a.id == account);
        let origin = nip46_origin(shared, &mut g, call.client, &label);
        let timeout = Duration::from_millis(shared.cfg.limits.default_timeout_ms);
        let (id, rx) = enqueue(
            shared,
            &mut g,
            &origin,
            Canonical::Pair {
                name: label,
                permissions: perms,
            },
            meta,
            None,
            ReplyKind::Connect,
            timeout,
            PendingExtra {
                text: app_url.map(|u| format!("app url: {u}")),
                fixed_account: Some(account),
                nostrconnect: None,
            },
        )?;
        (origin, id, rx, timeout)
    };
    drop(origin);
    wait_submitted(
        shared,
        Submitted::Wait { id, rx, timeout },
        shared.shutdown.child_token(),
    )
    .await?;
    Ok("ack".into())
}

/// Called after the user approved a NIP-46 pairing: remember the client's relays (for
/// `nostrconnect://`) and make the service listen on them.
pub fn after_pairing_approved(
    shared: &Arc<Shared>,
    g: &mut Inner,
    client: Pubkey32,
    ctx: Option<NostrConnectCtx>,
) {
    if let Some(ctx) = ctx {
        g.nip46.client_relays.insert(client, ctx.relays);
        let _ = persist(g);
    }
    let _ = shared; // `sync` is invoked by the caller after the lock is released
}

/// Called when a client is revoked or blocked.
pub fn forget_client(g: &mut Inner, client: &Pubkey32) {
    g.nip46.sessions.remove(client);
    if g.nip46.client_relays.remove(client).is_some() {
        let _ = persist(g);
    }
}
