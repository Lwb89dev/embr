//! The control channel: the privileged API of the GUI and CLI.
//!
//! It is a separate socket from the client API and requires the **vault password** (or a control
//! token issued after it) for everything except `status`. A client of the signer API cannot reach
//! it, so it cannot approve its own requests.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use embr_core::{AccountId, Pubkey32};
use embr_ipc::codec::{CodecError, encode_line, read_line_async, write_bytes_async};
use embr_ipc::control::{
    AccountIdParams, AddGeneratedParams, BackupParams, CONTROL_PROTOCOL, ChangePasswordParams,
    ClientKeyParams, ClientView, ControlEvent, ControlHello, DecideParams, DecisionWire,
    ExportNcryptsecParams, GrantIdParams, ImportNcryptsecParams, ImportSecretParams, LogParams,
    PasswordParams, PendingKind, RemoveAccountParams, RevealNsecParams, ScopeWire, SetLabelParams,
    Settings, TokenParams, UNAUTHENTICATED_METHODS, VaultState,
};
use embr_ipc::{ErrorCode, MAX_LINE_BYTES, Request, Response, RpcError, parse_params, valid_id};
use embr_policy::{AuditOutcome, AuditRecord, Choice, Engine, PolicyError, Scope};
use embr_vault::{Vault, VaultError};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::mpsc;

use crate::client_api::CountGuard;
use crate::state::{
    Done, POLICY_BLOB, ReplyKind, SETTINGS_BLOB, Shared, VaultSlot, map_vault_err, now_secs,
};

const MAX_CONTROL_CONNECTIONS: usize = 16;

/// Policy and settings blobs read while unlocking.
type LoadedBlobs = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

struct ConnState {
    auth_epoch: Option<u64>,
    subscribed: bool,
    /// Cancelled when the connection ends, so background forwarders stop too.
    closed: tokio_util::sync::CancellationToken,
}

fn rpc(code: ErrorCode, msg: &str) -> RpcError {
    RpcError::new(code, msg)
}

async fn send<T: Serialize>(tx: &mpsc::Sender<Vec<u8>>, v: &T) {
    if let Ok(b) = encode_line(v, MAX_LINE_BYTES) {
        let _ = tx.send(b).await;
    }
}

/// Serves one control connection.
pub(crate) async fn serve<S>(shared: Arc<Shared>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(_guard) =
        CountGuard::try_acquire(&shared, |s| &s.control_conns, MAX_CONTROL_CONNECTIONS)
    else {
        return;
    };
    // (The acceptor has already established that the peer is the daemon's own user.)
    let (rd, mut wr) = tokio::io::split(stream);
    let mut reader = BufReader::new(rd);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let writer = tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            if write_bytes_async(&mut wr, b).await.is_err() {
                break;
            }
        }
    });

    send(
        &tx,
        &ControlHello {
            embr_control: CONTROL_PROTOCOL,
            status: shared.status(),
        },
    )
    .await;
    let mut st = ConnState {
        auth_epoch: None,
        subscribed: false,
        closed: tokio_util::sync::CancellationToken::new(),
    };
    let mut malformed = 0u32;
    loop {
        let line = tokio::select! {
            _ = shared.shutdown.cancelled() => break,
            r = tokio::time::timeout(Duration::from_secs(3600), read_line_async(&mut reader, MAX_LINE_BYTES)) => match r {
                Ok(Ok(Some(l))) => l,
                Ok(Err(CodecError::TooLong)) => {
                    send(&tx, &Response::err("", rpc(ErrorCode::PayloadTooLarge, "line too long"))).await;
                    break;
                }
                _ => break,
            },
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                malformed += 1;
                send(
                    &tx,
                    &Response::err(
                        "",
                        rpc(
                            ErrorCode::InvalidRequest,
                            &format!("malformed request: {e}"),
                        ),
                    ),
                )
                .await;
                if malformed >= 5 {
                    break;
                }
                continue;
            }
        };
        malformed = 0;
        if !valid_id(&req.id) {
            send(
                &tx,
                &Response::err(
                    &req.id,
                    rpc(ErrorCode::InvalidRequest, "invalid request id"),
                ),
            )
            .await;
            continue;
        }
        let id = req.id.clone();
        let resp = match handle(&shared, &mut st, req, &tx).await {
            Ok(v) => Response::ok(&id, v),
            Err(e) => Response::err(&id, e),
        };
        send(&tx, &resp).await;
    }
    st.closed.cancel();
    drop(tx);
    let _ = writer.await;
}

fn require_auth(shared: &Arc<Shared>, st: &ConnState) -> Result<(), RpcError> {
    let g = shared.lock();
    if st.auth_epoch == Some(g.lock_epoch) && g.vault_state() == VaultState::Unlocked {
        Ok(())
    } else {
        Err(rpc(
            ErrorCode::Unauthenticated,
            "authenticate first (unlock, or auth with a control token)",
        ))
    }
}

fn policy_err(e: PolicyError) -> RpcError {
    match e {
        PolicyError::NotPaired | PolicyError::Blocked | PolicyError::AccountNotGranted => {
            rpc(ErrorCode::NotPaired, &e.to_string())
        }
        other => rpc(ErrorCode::InvalidParams, &other.to_string()),
    }
}

async fn handle(
    shared: &Arc<Shared>,
    st: &mut ConnState,
    req: Request,
    out: &mpsc::Sender<Vec<u8>>,
) -> Done {
    let method = req.method.as_str();
    let params = req.params;
    if !UNAUTHENTICATED_METHODS.contains(&method) {
        require_auth(shared, st)?;
    }
    // Only deliberate user actions keep the vault open; status polling and event streaming do not.
    if !matches!(
        method,
        "status" | "list_pending" | "subscribe" | "auth" | "unlock" | "create_vault"
    ) {
        shared.lock().touch_activity();
        shared.activity.notify_one();
    }

    match method {
        "status" => Ok(serde_json::to_value(shared.status()).unwrap_or(Value::Null)),
        "unlock" => {
            let p: PasswordParams = parse_params(params)?;
            let token = unlock(shared, p.password).await?;
            st.auth_epoch = Some(shared.lock().lock_epoch);
            Ok(json!({"token": token}))
        }
        "create_vault" => {
            let p: PasswordParams = parse_params(params)?;
            let token = create_vault(shared, p.password).await?;
            st.auth_epoch = Some(shared.lock().lock_epoch);
            Ok(json!({"token": token}))
        }
        "auth" => {
            let p: TokenParams = parse_params(params)?;
            let g = shared.lock();
            if g.vault_state() == VaultState::Unlocked && g.token_valid(&p.token) {
                st.auth_epoch = Some(g.lock_epoch);
                Ok(json!(true))
            } else {
                Err(rpc(ErrorCode::Unauthenticated, "invalid or expired token"))
            }
        }
        "lock" => {
            shared.lock_now("requested by the user");
            Ok(json!(true))
        }
        "subscribe" => {
            if !st.subscribed {
                st.subscribed = true;
                let mut rx = shared.subscribe();
                let tx = out.clone();
                let sh = shared.clone();
                let epoch = st.auth_epoch.unwrap_or(0);
                let closed = st.closed.clone();
                tokio::spawn(async move {
                    loop {
                        let ev = tokio::select! {
                            () = closed.cancelled() => break,
                            r = rx.recv() => match r {
                                Ok(ev) => ev,
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => ControlEvent::ClientsChanged,
                                Err(_) => break,
                            },
                        };
                        // After a lock this connection is no longer authenticated: it gets the
                        // `locked` notification and nothing else (no request details), then ends.
                        let stale = sh.lock().lock_epoch != epoch;
                        match ev {
                            ControlEvent::Locked => {
                                send(&tx, &ev).await;
                                break;
                            }
                            _ if stale => {}
                            ev => send(&tx, &ev).await,
                        }
                    }
                });
            }
            Ok(json!(true))
        }
        "change_password" => {
            let p: ChangePasswordParams = parse_params(params)?;
            shared
                .with_vault_blocking(move |v| v.change_password(&p.old, &p.new))
                .await?
                .map_err(map_vault_err)?;
            shared.lock().audit_admin("change_password", None);
            Ok(json!(true))
        }
        "export_backup" => {
            let p: BackupParams = parse_params(params)?;
            let dest = Path::new(&p.dest);
            if !dest.is_absolute() {
                return Err(rpc(
                    ErrorCode::InvalidParams,
                    "destination must be an absolute path",
                ));
            }
            let mut g = shared.lock();
            g.vault_ref()?.export_backup(dest).map_err(map_vault_err)?;
            g.audit_admin("export_backup", None);
            Ok(json!(true))
        }
        "list_accounts" => {
            let g = shared.lock();
            let v = g.vault_ref()?;
            let accounts = v.list_accounts().map_err(map_vault_err)?;
            let active = v.active_account().map_err(map_vault_err)?.map(|a| a.id);
            Ok(json!({"accounts": accounts, "active": active}))
        }
        "add_generated" => {
            let p: AddGeneratedParams = parse_params(params)?;
            let meta = shared
                .lock()
                .vault_mut()?
                .add_generated(&p.label)
                .map_err(map_vault_err)?;
            accounts_changed(shared, "add_account");
            Ok(serde_json::to_value(meta).unwrap_or(Value::Null))
        }
        "import_secret" => {
            let p: ImportSecretParams = parse_params(params)?;
            let meta = shared
                .lock()
                .vault_mut()?
                .import_secret(&p.label, &p.secret)
                .map_err(map_vault_err)?;
            accounts_changed(shared, "import_secret");
            Ok(serde_json::to_value(meta).unwrap_or(Value::Null))
        }
        "import_ncryptsec" => {
            let p: ImportNcryptsecParams = parse_params(params)?;
            let meta = shared
                .with_vault_blocking(move |v| {
                    v.import_ncryptsec(&p.label, &p.ncryptsec, &p.password)
                })
                .await?
                .map_err(map_vault_err)?;
            accounts_changed(shared, "import_ncryptsec");
            Ok(serde_json::to_value(meta).unwrap_or(Value::Null))
        }
        "set_active" => {
            let p: AccountIdParams = parse_params(params)?;
            shared
                .lock()
                .vault_mut()?
                .set_active(p.id)
                .map_err(map_vault_err)?;
            shared.emit(ControlEvent::AccountsChanged);
            Ok(json!(true))
        }
        "set_label" => {
            let p: SetLabelParams = parse_params(params)?;
            shared
                .lock()
                .vault_mut()?
                .set_label(p.id, &p.label)
                .map_err(map_vault_err)?;
            shared.emit(ControlEvent::AccountsChanged);
            Ok(json!(true))
        }
        "remove_account" => {
            let p: RemoveAccountParams = parse_params(params)?;
            if !p.confirm {
                return Err(rpc(
                    ErrorCode::InvalidParams,
                    "removing an account deletes its key; confirm must be true",
                ));
            }
            remove_account(shared, p.id)?;
            Ok(json!(true))
        }
        "export_ncryptsec" => {
            let p: ExportNcryptsecParams = parse_params(params)?;
            let s = shared
                .with_vault_blocking(move |v| {
                    v.export_ncryptsec(p.id, &p.vault_password, &p.export_password, p.log_n)
                })
                .await?
                .map_err(map_vault_err)?;
            shared.lock().audit_admin("export_ncryptsec", None);
            Ok(json!({"ncryptsec": s}))
        }
        "reveal_nsec" => {
            let p: RevealNsecParams = parse_params(params)?;
            let s = shared
                .with_vault_blocking(move |v| v.reveal_nsec(p.id, &p.vault_password))
                .await?
                .map_err(map_vault_err)?;
            shared
                .lock()
                .audit_admin("reveal_nsec", Some("the private key was shown to the user"));
            Ok(json!({"nsec": s.as_str()}))
        }
        "list_pending" => {
            let g = shared.lock();
            let views: Vec<_> = g.pending.values().map(|e| e.view.clone()).collect();
            Ok(serde_json::to_value(views).unwrap_or(Value::Null))
        }
        "decide" => {
            let p: DecideParams = parse_params(params)?;
            decide(shared, p)
        }
        "list_clients" => {
            let g = shared.lock();
            let views: Vec<ClientView> = g
                .policy
                .clients()
                .iter()
                .map(|c| ClientView {
                    record: c.clone(),
                    grants: g
                        .policy
                        .grants()
                        .iter()
                        .filter(|gr| gr.client == c.key)
                        .count(),
                    connected: g.sessions.values().filter(|s| s.client == c.key).count(),
                })
                .collect();
            Ok(serde_json::to_value(views).unwrap_or(Value::Null))
        }
        "list_grants" => {
            let g = shared.lock();
            Ok(serde_json::to_value(g.policy.grants()).unwrap_or(Value::Null))
        }
        "revoke_client" | "block_client" | "unblock_client" => {
            let p: ClientKeyParams = parse_params(params)?;
            policy_change(shared, method, p.key)?;
            Ok(json!(true))
        }
        "revoke_grant" => {
            let p: GrantIdParams = parse_params(params)?;
            let mut g = shared.lock();
            let removed = g.policy.revoke_grant(embr_policy::GrantId(p.id));
            if removed {
                g.persist_policy()?;
                g.audit_admin("revoke_grant", None);
            }
            drop(g);
            shared.emit(ControlEvent::ClientsChanged);
            Ok(json!(removed))
        }
        "get_settings" => Ok(serde_json::to_value(&shared.lock().settings).unwrap_or(Value::Null)),
        "set_settings" => {
            let mut s: Settings = parse_params(params)?;
            s.validate().map_err(|m| rpc(ErrorCode::InvalidParams, m))?;
            // Relays: normalise, drop duplicates, and refuse anything but wss:// (or loopback ws://).
            let mut relays = Vec::new();
            for r in &s.relays {
                let r = embr_nip46::uri::validate_relay(r)
                    .map_err(|e| rpc(ErrorCode::InvalidParams, &e.to_string()))?;
                if !relays.contains(&r) {
                    relays.push(r);
                }
            }
            s.relays = relays;
            let mut g = shared.lock();
            g.settings = s;
            g.persist_settings()?;
            g.audit_admin("set_settings", None);
            drop(g);
            shared.activity.notify_one();
            crate::nip46::sync(shared); // start/stop/update the relay service
            Ok(json!(true))
        }
        "nip46_status" => {
            Ok(serde_json::to_value(crate::nip46::status(shared)).unwrap_or(Value::Null))
        }
        "nip46_bunker" => {
            let p: embr_ipc::control::Nip46BunkerParams = parse_params(params)?;
            crate::nip46::create_bunker(shared, p.account)
        }
        "nip46_connect" => {
            let p: embr_ipc::control::Nip46ConnectParams = parse_params(params)?;
            crate::nip46::import_nostrconnect(shared, &p.uri, p.account).await
        }
        "recent_log" => {
            let p: LogParams = parse_params(params)?;
            let g = shared.lock();
            Ok(serde_json::to_value(g.recent_audit(p.limit)).unwrap_or(Value::Null))
        }
        other => Err(rpc(
            ErrorCode::UnsupportedMethod,
            &format!("unsupported control method {other:?}"),
        )),
    }
}

fn accounts_changed(shared: &Arc<Shared>, what: &str) {
    shared.lock().audit_admin(what, None);
    shared.emit(ControlEvent::AccountsChanged);
}

fn remove_account(shared: &Arc<Shared>, id: AccountId) -> Result<(), RpcError> {
    let mut g = shared.lock();
    g.vault_mut()?.remove_account(id).map_err(map_vault_err)?;
    g.policy.remove_account(id);
    g.persist_policy()?;
    g.nip46.remove_account(id);
    let _ = crate::nip46::persist(&mut g);
    g.cancel_pending_where(shared, "the account was removed", |e| e.account == Some(id));
    g.audit_admin("remove_account", None);
    drop(g);
    crate::nip46::sync(shared);
    shared.emit(ControlEvent::AccountsChanged);
    shared.emit(ControlEvent::ClientsChanged);
    Ok(())
}

fn policy_change(shared: &Arc<Shared>, method: &str, key: Pubkey32) -> Result<(), RpcError> {
    let mut g = shared.lock();
    match method {
        "revoke_client" => {
            g.policy.revoke_client(&key);
        }
        "block_client" => g.policy.block_client(key),
        _ => {
            g.policy.unblock_client(&key);
        }
    }
    g.persist_policy()?;
    if method != "unblock_client" {
        g.cancel_pending_where(shared, "the client was revoked", |e| e.client == key);
        crate::nip46::forget_client(&mut g, &key);
    }
    g.audit(&AuditRecord {
        ts: now_secs(),
        via: "control".into(),
        client: Some(key),
        client_name: None,
        account: None,
        action: method.into(),
        kind: None,
        outcome: AuditOutcome::Revoked,
        grant: None,
        note: None,
    });
    drop(g);
    shared.emit(ControlEvent::ClientsChanged);
    Ok(())
}

// ===== unlock / create =================================================================

async fn unlock(shared: &Arc<Shared>, password: String) -> Result<String, RpcError> {
    {
        let g = shared.lock();
        if let Err(secs) = g.unlock_allowed() {
            return Err(rpc(
                ErrorCode::RateLimited,
                "too many wrong passwords; wait before trying again",
            )
            .with_data(json!({"retry_after_ms": secs * 1000})));
        }
    }
    let result = shared
        .with_vault_blocking(move |v| -> Result<Option<LoadedBlobs>, VaultError> {
            if v.is_unlocked() {
                v.verify_password(&password)?;
                Ok(None)
            } else {
                v.unlock(&password)?;
                Ok(Some((
                    v.blob(POLICY_BLOB)?,
                    v.blob(SETTINGS_BLOB)?,
                    v.blob(crate::nip46::NIP46_BLOB)?,
                )))
            }
        })
        .await?;
    let free = shared.cfg.limits.unlock_free_attempts;
    match result {
        Err(VaultError::WrongPasswordOrCorrupt) => {
            shared.lock().note_unlock_failure(free);
            Err(rpc(
                ErrorCode::Unauthenticated,
                "wrong password or corrupted vault",
            ))
        }
        Err(e) => Err(map_vault_err(e)),
        Ok(loaded) => {
            let mut g = shared.lock();
            g.note_unlock_success();
            let newly = loaded.is_some();
            if let Some((policy, settings, nip46_blob)) = loaded {
                g.nip46 = crate::nip46::Nip46State::load(nip46_blob);
                g.policy = policy
                    .as_deref()
                    .and_then(|b| Engine::from_json(b, now_secs()).ok())
                    .unwrap_or_default();
                g.settings = settings
                    .as_deref()
                    .and_then(|b| serde_json::from_slice::<Settings>(b).ok())
                    .filter(|s| s.validate().is_ok())
                    .unwrap_or_default();
            }
            g.touch_activity();
            let token = g.issue_token()?;
            if newly {
                g.audit_admin("unlock", None);
            }
            drop(g);
            shared.activity.notify_one();
            if newly {
                shared.emit(ControlEvent::Unlocked);
                crate::nip46::sync(shared); // starts the relay service only if remote signing is enabled
            }
            Ok(token)
        }
    }
}

async fn create_vault(shared: &Arc<Shared>, password: String) -> Result<String, RpcError> {
    {
        let mut g = shared.lock();
        match g.vault {
            VaultSlot::Missing => g.vault = VaultSlot::Busy,
            _ => return Err(rpc(ErrorCode::InvalidRequest, "a vault already exists")),
        }
    }
    let (path, kdf) = (shared.cfg.vault_path(), shared.cfg.kdf);
    let created =
        tokio::task::spawn_blocking(move || Vault::create_with(path, &password, kdf)).await;
    let mut g = shared.lock();
    match created {
        Ok(Ok(v)) => {
            g.vault = VaultSlot::Present(Box::new(v));
            g.policy = Engine::new();
            g.settings = Settings::default();
            g.touch_activity();
            g.audit_admin("create_vault", None);
            let token = g.issue_token()?;
            drop(g);
            shared.activity.notify_one();
            shared.emit(ControlEvent::Unlocked);
            Ok(token)
        }
        Ok(Err(e)) => {
            g.vault = VaultSlot::Missing;
            Err(map_vault_err(e))
        }
        Err(_) => {
            g.vault = VaultSlot::Missing;
            Err(rpc(ErrorCode::Internal, "internal error"))
        }
    }
}

// ===== decisions =======================================================================

fn decide(shared: &Arc<Shared>, p: DecideParams) -> Done {
    let limits = shared.crypto_limits();
    let mut g = shared.lock();
    g.vault_ref()?;
    let now = now_secs();

    let Some(entry) = g.pending.get(&p.id) else {
        return Err(rpc(
            ErrorCode::InvalidParams,
            "no such pending request (it may have expired or been cancelled)",
        ));
    };
    if entry.view.digest != p.digest {
        return Err(rpc(
            ErrorCode::InvalidParams,
            "the request does not match what was reviewed; review it again",
        ));
    }
    let kind = entry.view.kind;
    let (client, session, reply) = (entry.client, entry.session, entry.reply);
    let (fixed_account, nostrconnect) = (entry.fixed_account, entry.nostrconnect.clone());
    let via = entry.view.client.via.clone();
    let name = entry.view.client.name.clone();
    let preq = entry.request;

    // Decisions that need no further validation against the policy.
    if p.decision == DecisionWire::BlockClient {
        g.policy.block_client(client);
        g.persist_policy()?;
        g.resolve(
            shared,
            p.id,
            Err(rpc(ErrorCode::Denied, "this client was blocked")),
            "rejected",
            AuditOutcome::DeniedByUser,
        );
        g.cancel_pending_where(shared, "the client was blocked", |e| e.client == client);
        drop(g);
        shared.emit(ControlEvent::ClientsChanged);
        return Ok(json!({"decided": "block_client"}));
    }

    match kind {
        PendingKind::Pair => match p.decision {
            DecisionWire::Pair { account } => {
                let accounts = g.accounts()?;
                let meta = accounts
                    .iter()
                    .find(|a| a.id == account)
                    .ok_or_else(|| rpc(ErrorCode::AccountNotFound, "no such account"))?
                    .clone();
                if fixed_account.is_some_and(|f| f != account) {
                    return Err(rpc(
                        ErrorCode::InvalidParams,
                        "this connection is bound to a specific account; approve it with that account",
                    ));
                }
                g.policy
                    .pair_via(client, &name, vec![account], now, &via)
                    .map_err(policy_err)?;
                g.persist_policy()?;
                if via == "nip46" {
                    crate::nip46::after_pairing_approved(shared, &mut g, client, nostrconnect);
                }
                let result = match reply {
                    ReplyKind::GetPublicKey => json!(meta.pubkey_hex),
                    _ => json!({"paired": true, "account": meta.pubkey_hex}),
                };
                g.resolve(shared, p.id, Ok(result), "approved", AuditOutcome::Paired);
                drop(g);
                if via == "nip46" {
                    crate::nip46::sync(shared); // listen on the client's relays, now that it is approved
                }
                shared.emit(ControlEvent::ClientsChanged);
                Ok(json!({"decided": "pair"}))
            }
            DecisionWire::RejectOnce | DecisionWire::AlwaysReject => {
                g.resolve(
                    shared,
                    p.id,
                    Err(rpc(ErrorCode::Denied, "pairing was rejected")),
                    "rejected",
                    AuditOutcome::DeniedByUser,
                );
                Ok(json!({"decided": "reject"}))
            }
            _ => Err(rpc(
                ErrorCode::InvalidParams,
                "a pairing request accepts only pair, reject_once, always_reject or block_client",
            )),
        },
        PendingKind::Operation => {
            let preq = preq
                .ok_or_else(|| rpc(ErrorCode::Internal, "pending request without policy data"))?;
            let choice = match p.decision {
                DecisionWire::AllowOnce => Choice::AllowOnce,
                DecisionWire::AllowSession => Choice::AllowSession,
                DecisionWire::AllowUntil { until } => Choice::AllowUntil(until),
                DecisionWire::AllowPersistent => Choice::AllowPersistent,
                DecisionWire::RejectOnce => Choice::RejectOnce,
                DecisionWire::AlwaysReject => Choice::AlwaysReject,
                DecisionWire::Pair { .. } | DecisionWire::BlockClient => {
                    return Err(rpc(
                        ErrorCode::InvalidParams,
                        "this decision is only valid for pairing requests",
                    ));
                }
            };
            let scope = p.scope.map_or_else(
                || Scope::exact(&preq),
                |s: ScopeWire| Scope {
                    kind: s.kind,
                    peer: s.peer,
                    uses: s.uses,
                },
            );
            // A refused choice (too broad, bad scope…) leaves the request pending so the user can
            // choose again.
            let decision = g
                .policy
                .decide(&preq, choice, &scope, session, now)
                .map_err(policy_err)?;
            let remembered = decision.grant.is_some();
            if remembered {
                g.persist_policy()?;
            }
            let Some(entry) = g.pending.remove(&p.id) else {
                return Err(rpc(ErrorCode::InvalidParams, "the request is gone"));
            };
            if decision.allow {
                let result = g
                    .vault_ref()
                    .and_then(|v| {
                        v.with_identity(preq.account, |id| entry.canonical.execute(id, &limits))
                            .map_err(map_vault_err)
                    })
                    .and_then(|r| r);
                g.finish_entry(
                    shared,
                    p.id,
                    entry,
                    result,
                    "approved",
                    AuditOutcome::AllowedByUser,
                );
            } else {
                g.finish_entry(
                    shared,
                    p.id,
                    entry,
                    Err(rpc(ErrorCode::Denied, "rejected by the user")),
                    "rejected",
                    AuditOutcome::DeniedByUser,
                );
            }
            drop(g);
            if remembered {
                shared.emit(ControlEvent::ClientsChanged);
            }
            Ok(
                json!({"decided": if decision.allow { "allow" } else { "reject" }, "grant": decision.grant.map(|g| g.0)}),
            )
        }
    }
}
