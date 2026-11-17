//! The client API: one task per connection, one task per in-flight request.
//!
//! Security properties enforced here (each has an end-to-end test in `tests/e2e.rs`):
//! * only the daemon's own uid may connect (peer credentials);
//! * nothing is served before a valid proof of possession of the client key;
//! * unknown clients can only pair; paired clients only get what the policy engine allows;
//! * every request is parsed strictly, size-limited, rate-limited and id-checked;
//! * pending approvals are bounded, expire, and are cancelled on disconnect or lock;
//! * the request that is displayed, approved and executed is one stored canonical copy.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use embr_core::display::sanitize;
use embr_core::{AccountMeta, Operation, Pubkey32};
use embr_ipc::codec::{CodecError, encode_line, read_line_async, write_bytes_async};
use embr_ipc::control::{ClientIdent, ControlEvent, PeerHint};
use embr_ipc::{
    AccountParams, CancelParams, ClientHello, ConnectParams, DecryptParams, EncryptParams,
    ErrorCode, HelloReply, MAX_LINE_BYTES, METHODS, PROTOCOL_VERSION, Request, Response, RpcError,
    ServerHello, SignEventParams, auth, parse_params, valid_id,
};
use embr_policy::{AuditOutcome, AuditRecord, ClientRecord, SessionId, Verdict};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::canonical::Canonical;
use crate::state::{Done, Inner, ReplyKind, Shared, now_secs};

const MAX_INFLIGHT: usize = 32;
const SEEN_IDS: usize = 4096;
const MAX_CONSECUTIVE_MALFORMED: u32 = 5;

/// Decrements a counter when dropped.
pub(crate) struct CountGuard(Arc<Shared>, fn(&Shared) -> &AtomicUsize);

impl CountGuard {
    pub(crate) fn try_acquire(
        shared: &Arc<Shared>,
        which: fn(&Shared) -> &AtomicUsize,
        max: usize,
    ) -> Option<Self> {
        let c = which(shared);
        if c.fetch_add(1, Ordering::AcqRel) >= max {
            c.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(CountGuard(shared.clone(), which))
    }
}

impl Drop for CountGuard {
    fn drop(&mut self) {
        (self.1)(&self.0).fetch_sub(1, Ordering::AcqRel);
    }
}

/// Who is asking and over which transport. Shared by the local client API and NIP-46, so that
/// **one** `submit` function (one policy decision point) serves both.
pub(crate) struct Origin {
    pub(crate) session: SessionId,
    pub(crate) client: Pubkey32,
    /// Self-declared label, already sanitised (untrusted).
    pub(crate) client_name: String,
    /// Process hints (local connections only).
    pub(crate) peer: Option<PeerHint>,
    /// `"local"` or `"nip46"`.
    pub(crate) via: &'static str,
}

/// State of one authenticated connection.
struct Conn {
    origin: Origin,
    tx: mpsc::Sender<Vec<u8>>,
    token: CancellationToken,
}

impl std::ops::Deref for Conn {
    type Target = Origin;
    fn deref(&self) -> &Origin {
        &self.origin
    }
}

async fn send<T: Serialize>(tx: &mpsc::Sender<Vec<u8>>, v: &T) {
    if let Ok(bytes) = encode_line(v, MAX_LINE_BYTES) {
        let _ = tx.send(bytes).await;
    }
}

/// Serves one client connection until it closes.
pub(crate) async fn serve<S>(shared: Arc<Shared>, stream: S, peer: PeerHint)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = shared.cfg.limits.clone();
    let Some(_total) =
        CountGuard::try_acquire(&shared, |s| &s.client_conns, limits.max_connections)
    else {
        return;
    };
    let Some(unauth) =
        CountGuard::try_acquire(&shared, |s| &s.unauth_conns, limits.max_unauthenticated)
    else {
        return;
    };
    // (The acceptor has already established that the peer is the daemon's own user.)

    let (rd, mut wr) = tokio::io::split(stream);
    let mut reader = BufReader::new(rd);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if write_bytes_async(&mut wr, bytes).await.is_err() {
                break;
            }
        }
    });

    let conn = match handshake(&shared, &mut reader, &tx, peer).await {
        Some(c) => c,
        None => {
            drop(tx);
            let _ = writer.await;
            return;
        }
    };
    drop(unauth); // handshake done: no longer counts against the unauthenticated cap

    let conn = Arc::new(conn);
    run_requests(&shared, &conn, &mut reader).await;

    // Cleanup: cancel in-flight requests, forget the session and its session-scoped grants.
    conn.token.cancel();
    {
        let mut g = shared.lock();
        g.sessions.remove(&conn.session);
        g.policy.end_session(conn.session);
    }
    // Let request tasks drain their final messages before the writer closes.
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(conn);
    let _ = writer.await;
}

async fn reject_hello(tx: &mpsc::Sender<Vec<u8>>, code: ErrorCode, msg: &str) -> Option<Conn> {
    send(
        tx,
        &HelloReply {
            ok: false,
            session: None,
            paired: None,
            locked: false,
            error: Some(RpcError::new(code, msg)),
        },
    )
    .await;
    None
}

async fn handshake<R: AsyncBufRead + Unpin>(
    shared: &Arc<Shared>,
    reader: &mut R,
    tx: &mpsc::Sender<Vec<u8>>,
    peer: PeerHint,
) -> Option<Conn> {
    let nonce = auth::new_nonce().ok()?;
    send(
        tx,
        &ServerHello {
            embr: PROTOCOL_VERSION,
            name: "Embr".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: vec![PROTOCOL_VERSION],
            methods: METHODS.iter().map(|m| (*m).to_owned()).collect(),
            nonce: nonce.clone(),
        },
    )
    .await;

    let deadline = Duration::from_secs(shared.cfg.limits.handshake_secs);
    let line = match tokio::time::timeout(deadline, read_line_async(reader, MAX_LINE_BYTES)).await {
        Ok(Ok(Some(l))) => l,
        Ok(Err(CodecError::TooLong)) => {
            return reject_hello(tx, ErrorCode::PayloadTooLarge, "hello too large").await;
        }
        _ => return None, // timeout, EOF, I/O: just close
    };
    let Ok(hello) = serde_json::from_str::<ClientHello>(&line) else {
        return reject_hello(tx, ErrorCode::InvalidRequest, "malformed hello").await;
    };
    let hello = hello.hello;
    if hello.protocol != PROTOCOL_VERSION {
        return reject_hello(
            tx,
            ErrorCode::InvalidRequest,
            "unsupported protocol version",
        )
        .await;
    }
    let Ok(client) = hello.client.pubkey.parse::<Pubkey32>() else {
        return reject_hello(tx, ErrorCode::InvalidRequest, "bad client pubkey").await;
    };
    if auth::verify_proof(&hello.proof, &nonce, &client, now_secs()).is_err() {
        return reject_hello(
            tx,
            ErrorCode::Unauthenticated,
            "invalid proof of possession",
        )
        .await;
    }

    let name = {
        let n = sanitize(hello.client.name.trim(), 64);
        if n.is_empty() {
            "unnamed".to_owned()
        } else {
            n
        }
    };
    let session = shared.new_session();
    // Decide under the lock, without awaiting while it is held.
    let admission: Result<(Option<bool>, bool), ()> = {
        let mut g = shared.lock();
        if g.vault_ref().is_ok() {
            if g.policy.is_blocked(&client) {
                Err(())
            } else {
                let paired = g.policy.client(&client).is_some();
                g.sessions
                    .insert(session, crate::state::SessionRec { client });
                Ok((Some(paired), false))
            }
        } else {
            g.sessions
                .insert(session, crate::state::SessionRec { client });
            Ok((None, true))
        }
    };
    let Ok((paired, locked)) = admission else {
        return reject_hello(tx, ErrorCode::Denied, "this client is blocked").await;
    };
    send(
        tx,
        &HelloReply {
            ok: true,
            session: Some(format!("{:016x}", session.0)),
            paired,
            locked,
            error: None,
        },
    )
    .await;
    Some(Conn {
        origin: Origin {
            session,
            client,
            client_name: name,
            peer: Some(peer),
            via: "local",
        },
        tx: tx.clone(),
        token: CancellationToken::new(),
    })
}

async fn run_requests<R: AsyncBufRead + Unpin>(
    shared: &Arc<Shared>,
    conn: &Arc<Conn>,
    reader: &mut R,
) {
    let idle = Duration::from_secs(shared.cfg.limits.idle_secs);
    let inflight: Arc<std::sync::Mutex<HashMap<String, CancellationToken>>> = Arc::default();
    let count = Arc::new(AtomicUsize::new(0));
    let mut seen: HashSet<String> = HashSet::new();
    let mut order: VecDeque<String> = VecDeque::new();
    let mut malformed = 0u32;

    loop {
        let line = tokio::select! {
            _ = shared.shutdown.cancelled() => return,
            r = tokio::time::timeout(idle, read_line_async(reader, MAX_LINE_BYTES)) => match r {
                Err(_) => return, // idle timeout
                Ok(Ok(Some(l))) => l,
                Ok(Ok(None)) => return,
                Ok(Err(CodecError::TooLong)) => {
                    send(&conn.tx, &Response::err("", RpcError::new(ErrorCode::PayloadTooLarge, "line too long"))).await;
                    return;
                }
                Ok(Err(_)) => return,
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
                    &conn.tx,
                    &Response::err(
                        "",
                        RpcError::new(ErrorCode::InvalidRequest, format!("malformed request: {e}")),
                    ),
                )
                .await;
                if malformed >= MAX_CONSECUTIVE_MALFORMED {
                    return;
                }
                continue;
            }
        };
        malformed = 0;
        if !valid_id(&req.id) || seen.contains(&req.id) {
            send(
                &conn.tx,
                &Response::err(
                    &req.id,
                    RpcError::new(ErrorCode::InvalidRequest, "invalid or duplicate request id"),
                ),
            )
            .await;
            continue;
        }
        seen.insert(req.id.clone());
        order.push_back(req.id.clone());
        if order.len() > SEEN_IDS {
            if let Some(old) = order.pop_front() {
                seen.remove(&old);
            }
        }

        // Rate limit and in-flight cap *before* spawning any work.
        let limited = {
            let mut g = shared.lock();
            let now_ms = u64::try_from(shared.uptime().as_millis()).unwrap_or(u64::MAX);
            g.limiter.check(&conn.client, now_ms)
        };
        if let Err(retry) = limited {
            record(
                shared,
                conn,
                "rate_limited",
                None,
                AuditOutcome::RateLimited,
                None,
            );
            send(
                &conn.tx,
                &Response::err(
                    &req.id,
                    RpcError::new(ErrorCode::RateLimited, "too many requests")
                        .with_data(json!({"retry_after_ms": retry})),
                ),
            )
            .await;
            continue;
        }
        if count.load(Ordering::Acquire) >= MAX_INFLIGHT {
            send(
                &conn.tx,
                &Response::err(
                    &req.id,
                    RpcError::new(ErrorCode::RateLimited, "too many requests in flight"),
                ),
            )
            .await;
            continue;
        }

        // `cancel` is handled inline so it cannot be starved behind the request it cancels.
        if req.method == "cancel" {
            let resp = match parse_params::<CancelParams>(req.params.clone()) {
                Ok(p) => match inflight
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&p.id)
                {
                    Some(t) => {
                        t.cancel();
                        Response::ok(&req.id, json!(true))
                    }
                    None => Response::err(
                        &req.id,
                        RpcError::new(ErrorCode::InvalidParams, "no such request in flight"),
                    ),
                },
                Err(e) => Response::err(&req.id, e),
            };
            send(&conn.tx, &resp).await;
            continue;
        }

        let token = conn.token.child_token();
        inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(req.id.clone(), token.clone());
        count.fetch_add(1, Ordering::AcqRel);
        let (shared, conn, inflight, count) = (
            shared.clone(),
            conn.clone(),
            inflight.clone(),
            count.clone(),
        );
        tokio::spawn(async move {
            let id = req.id.clone();
            let done = dispatch(&shared, &conn, req, token).await;
            let resp = match done {
                Ok(v) => Response::ok(&id, v),
                Err(e) => Response::err(&id, e),
            };
            send(&conn.tx, &resp).await;
            inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            count.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

fn record(
    shared: &Arc<Shared>,
    conn: &Conn,
    action: &str,
    kind: Option<u16>,
    outcome: AuditOutcome,
    grant: Option<u64>,
) {
    let mut g = shared.lock();
    g.audit(&AuditRecord {
        ts: now_secs(),
        via: conn.via.into(),
        client: Some(conn.client),
        client_name: Some(conn.client_name.clone()),
        account: None,
        action: action.to_owned(),
        kind,
        outcome,
        grant,
        note: None,
    });
}

/// Builds the canonical request once the account (and thus its public key) is known.
type CanonicalBuilder = Box<dyn FnOnce(&str) -> Result<Canonical, RpcError>>;

pub(crate) enum Submitted {
    Done(Done),
    Wait {
        id: u64,
        rx: oneshot::Receiver<Done>,
        timeout: Duration,
    },
}

async fn dispatch(
    shared: &Arc<Shared>,
    conn: &Arc<Conn>,
    req: Request,
    cancel: CancellationToken,
) -> Done {
    let submitted = submit(shared, &conn.origin, &req);
    wait_submitted(shared, submitted, cancel).await
}

/// Waits for a [`Submitted`] request: immediate results pass through; queued ones wait for the
/// user, a timeout, or cancellation (disconnect / shutdown), resolving the queue entry either way.
pub(crate) async fn wait_submitted(
    shared: &Arc<Shared>,
    submitted: Submitted,
    cancel: CancellationToken,
) -> Done {
    match submitted {
        Submitted::Done(d) => d,
        Submitted::Wait {
            id,
            mut rx,
            timeout,
        } => {
            tokio::select! {
                r = &mut rx => r.unwrap_or_else(|_| Err(RpcError::new(ErrorCode::Cancelled, "the signer is shutting down"))),
                () = tokio::time::sleep(timeout) => {
                    shared.lock().resolve(shared, id, Err(RpcError::new(ErrorCode::Expired, "timed out waiting for the user")), "expired", AuditOutcome::Expired);
                    rx.await.unwrap_or_else(|_| Err(RpcError::new(ErrorCode::Expired, "timed out")))
                }
                () = cancel.cancelled() => {
                    shared.lock().resolve(shared, id, Err(RpcError::new(ErrorCode::Cancelled, "cancelled")), "cancelled", AuditOutcome::Cancelled);
                    rx.await.unwrap_or_else(|_| Err(RpcError::new(ErrorCode::Cancelled, "cancelled")))
                }
            }
        }
    }
}

fn ident(conn: &Origin) -> ClientIdent {
    ClientIdent {
        pubkey: conn.client,
        name: conn.client_name.clone(),
        peer: conn.peer.clone(),
        via: conn.via.into(),
    }
}

/// Resolves the account a request targets. Unknown and not-granted accounts give the same error,
/// so a client cannot probe which accounts exist.
pub(crate) fn resolve_account(
    g: &Inner,
    rec: &ClientRecord,
    selector: Option<&str>,
) -> Result<AccountMeta, RpcError> {
    let accounts = g.accounts()?;
    let not_found = || {
        RpcError::new(
            ErrorCode::AccountNotFound,
            "account not found or not granted to this client",
        )
    };
    let meta = match selector {
        Some(s) => {
            let pk = embr_crypto::parse_public_key(s)
                .map_err(|e| RpcError::new(ErrorCode::InvalidParams, e.to_string()))?
                .to_hex();
            accounts.into_iter().find(|a| a.pubkey_hex == pk)
        }
        None => rec
            .accounts
            .iter()
            .find_map(|id| accounts.iter().find(|a| a.id == *id).cloned()),
    }
    .ok_or_else(not_found)?;
    if rec.accounts.contains(&meta.id) {
        Ok(meta)
    } else {
        Err(not_found())
    }
}

fn timeout_of(shared: &Shared, req: &Request) -> Duration {
    let l = &shared.cfg.limits;
    Duration::from_millis(
        req.timeout_ms
            .unwrap_or(l.default_timeout_ms)
            .clamp(1, l.max_timeout_ms),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn enqueue(
    shared: &Arc<Shared>,
    g: &mut Inner,
    conn: &Origin,
    canonical: Canonical,
    account: Option<AccountMeta>,
    request: Option<embr_policy::Request>,
    reply: ReplyKind,
    timeout: Duration,
    extra: crate::state::PendingExtra,
) -> Result<(u64, oneshot::Receiver<Done>), RpcError> {
    let l = &shared.cfg.limits;
    if g.pending_of(&conn.client) >= l.pending_per_client || g.pending.len() >= l.pending_total {
        return Err(RpcError::new(
            ErrorCode::RateLimited,
            "too many requests are waiting for approval",
        ));
    }
    let id = g.next_pending_id();
    let now = now_secs();
    let acct32 = account
        .as_ref()
        .and_then(|a| a.pubkey_hex.parse::<Pubkey32>().ok());
    let digest = canonical.digest(&conn.client, acct32.as_ref());
    let mut view = canonical.view(
        id,
        digest,
        ident(conn),
        account.clone(),
        now,
        now + timeout.as_secs().max(1),
    );
    view.text_preview = extra.text.clone().or(view.text_preview);
    let (tx, rx) = oneshot::channel();
    g.pending.insert(
        id,
        crate::state::PendingEntry {
            view: view.clone(),
            canonical,
            request,
            session: conn.session,
            client: conn.client,
            client_name: conn.client_name.clone(),
            account: account.map(|a| a.id),
            reply,
            tx: Some(tx),
            fixed_account: extra.fixed_account,
            nostrconnect: extra.nostrconnect,
        },
    );
    shared.emit(ControlEvent::PendingAdded {
        request: Box::new(view),
    });
    Ok((id, rx))
}

pub(crate) fn submit(shared: &Arc<Shared>, conn: &Origin, req: &Request) -> Submitted {
    match submit_inner(shared, conn, req) {
        Ok(s) => s,
        Err(e) => Submitted::Done(Err(e)),
    }
}

fn submit_inner(shared: &Arc<Shared>, conn: &Origin, req: &Request) -> Result<Submitted, RpcError> {
    let timeout = timeout_of(shared, req);
    let limits = shared.crypto_limits();
    let mut g = shared.lock();
    let now = now_secs();

    if req.method == "ping" {
        return Ok(Submitted::Done(Ok(json!("pong"))));
    }
    if !METHODS.contains(&req.method.as_str()) {
        return Err(RpcError::new(
            ErrorCode::UnsupportedMethod,
            format!("unsupported method {:?}", req.method),
        ));
    }
    // Locked (or busy) vault: answer immediately instead of hanging, after the shape checks below
    // would have been possible — Amber reports malformed requests first; we only need the state.
    g.vault_ref()?;

    let paired = g.policy.client(&conn.client).cloned();
    if g.policy.is_blocked(&conn.client) {
        return Err(RpcError::new(ErrorCode::Denied, "this client is blocked"));
    }
    g.policy.touch(&conn.client, now);

    match req.method.as_str() {
        "connect" | "get_public_key" => {
            let (selector, permissions, label) = if req.method == "connect" {
                let p: ConnectParams = parse_params(req.params.clone())?;
                (None, p.permissions, p.label)
            } else {
                let p: AccountParams = parse_params(req.params.clone())?;
                (p.account, Vec::new(), None)
            };
            let reply = if req.method == "connect" {
                ReplyKind::Connect
            } else {
                ReplyKind::GetPublicKey
            };
            if let Some(rec) = paired {
                let meta = resolve_account(&g, &rec, selector.as_deref())?;
                let verdict = g.policy.evaluate(
                    &embr_policy::Request {
                        client: conn.client,
                        account: meta.id,
                        op: Operation::GetPublicKey,
                        kind: None,
                        peer: None,
                    },
                    conn.session,
                    now,
                );
                return match verdict {
                    Verdict::Allow { .. } => Ok(Submitted::Done(Ok(match reply {
                        ReplyKind::Connect => json!({"paired": true, "account": meta.pubkey_hex}),
                        _ => json!(meta.pubkey_hex),
                    }))),
                    _ => Err(RpcError::new(
                        ErrorCode::AccountNotFound,
                        "account not granted to this client",
                    )),
                };
            }
            // Unpaired: ask the user. The `account` selector of an unpaired client is ignored — the
            // user chooses the account, and an unpaired client learns nothing about the vault.
            let permissions: Vec<String> = permissions
                .iter()
                .take(32)
                .map(|p| sanitize(p, 64))
                .collect();
            let name = label.map_or_else(|| conn.client_name.clone(), |l| sanitize(l.trim(), 64));
            let canonical = Canonical::Pair { name, permissions };
            let (id, rx) = enqueue(
                shared,
                &mut g,
                conn,
                canonical,
                None,
                None,
                reply,
                timeout,
                crate::state::PendingExtra::default(),
            )?;
            Ok(Submitted::Wait { id, rx, timeout })
        }
        "list_accounts" => {
            let rec = paired.ok_or_else(|| {
                RpcError::new(ErrorCode::NotPaired, "pair this client first (connect)")
            })?;
            let accounts = g.accounts()?;
            let list: Vec<Value> = rec
                .accounts
                .iter()
                .filter_map(|id| accounts.iter().find(|a| a.id == *id))
                .map(|a| json!({"pubkey": a.pubkey_hex, "npub": a.npub, "label": a.label}))
                .collect();
            Ok(Submitted::Done(Ok(Value::Array(list))))
        }
        "revoke_self" => {
            g.policy.revoke_client(&conn.client);
            g.persist_policy()?;
            g.audit(&AuditRecord {
                ts: now,
                via: conn.via.into(),
                client: Some(conn.client),
                client_name: Some(conn.client_name.clone()),
                account: None,
                action: "revoke_self".into(),
                kind: None,
                outcome: AuditOutcome::Revoked,
                grant: None,
                note: None,
            });
            drop(g);
            shared.emit(ControlEvent::ClientsChanged);
            Ok(Submitted::Done(Ok(json!(true))))
        }
        method => {
            let rec = paired.ok_or_else(|| {
                RpcError::new(ErrorCode::NotPaired, "pair this client first (connect)")
            })?;
            let (op, selector, canonical_of): (Operation, Option<String>, CanonicalBuilder) =
                match method {
                    "sign_event" => {
                        let p: SignEventParams = parse_params(req.params.clone())?;
                        let l = limits.clone();
                        (
                            Operation::SignEvent,
                            p.account,
                            Box::new(move |acct| Canonical::sign(p.event, acct, &l)),
                        )
                    }
                    "nip44_encrypt" | "nip04_encrypt" => {
                        let p: EncryptParams = parse_params(req.params.clone())?;
                        let op = if method == "nip44_encrypt" {
                            Operation::Nip44Encrypt
                        } else {
                            Operation::Nip04Encrypt
                        };
                        let l = limits.clone();
                        (
                            op,
                            p.account,
                            Box::new(move |_| Canonical::crypto(op, &p.peer, p.plaintext, &l)),
                        )
                    }
                    "nip44_decrypt" | "nip04_decrypt" => {
                        let p: DecryptParams = parse_params(req.params.clone())?;
                        let op = if method == "nip44_decrypt" {
                            Operation::Nip44Decrypt
                        } else {
                            Operation::Nip04Decrypt
                        };
                        let l = limits.clone();
                        (
                            op,
                            p.account,
                            Box::new(move |_| Canonical::crypto(op, &p.peer, p.payload, &l)),
                        )
                    }
                    _ => {
                        return Err(RpcError::new(
                            ErrorCode::UnsupportedMethod,
                            "unsupported method",
                        ));
                    }
                };
            let meta = resolve_account(&g, &rec, selector.as_deref())?;
            // Malformed requests are rejected here, *before* any prompt can be created.
            let canonical = canonical_of(&meta.pubkey_hex)?;
            let preq = embr_policy::Request {
                client: conn.client,
                account: meta.id,
                op,
                kind: canonical.kind(),
                peer: canonical.peer(),
            };
            match g.policy.evaluate(&preq, conn.session, now) {
                Verdict::Allow { grant } => {
                    let result = g
                        .vault_ref()?
                        .with_identity(meta.id, |id| canonical.execute(id, &limits))
                        .map_err(crate::state::map_vault_err)??;
                    g.audit(&AuditRecord {
                        ts: now,
                        via: conn.via.into(),
                        client: Some(conn.client),
                        client_name: Some(conn.client_name.clone()),
                        account: Some(meta.id),
                        action: op.as_str().into(),
                        kind: preq.kind,
                        outcome: AuditOutcome::AllowedByGrant,
                        grant: grant.map(|g| g.0),
                        note: None,
                    });
                    Ok(Submitted::Done(Ok(result)))
                }
                Verdict::Deny { grant } => {
                    g.audit(&AuditRecord {
                        ts: now,
                        via: conn.via.into(),
                        client: Some(conn.client),
                        client_name: Some(conn.client_name.clone()),
                        account: Some(meta.id),
                        action: op.as_str().into(),
                        kind: preq.kind,
                        outcome: AuditOutcome::DeniedByGrant,
                        grant: Some(grant.0),
                        note: None,
                    });
                    Err(RpcError::new(
                        ErrorCode::Denied,
                        "rejected by a stored permission rule",
                    ))
                }
                Verdict::Ask => {
                    let (id, rx) = enqueue(
                        shared,
                        &mut g,
                        conn,
                        canonical,
                        Some(meta),
                        Some(preq),
                        ReplyKind::Operation,
                        timeout,
                        crate::state::PendingExtra::default(),
                    )?;
                    Ok(Submitted::Wait { id, rx, timeout })
                }
                Verdict::NotPaired => {
                    Err(RpcError::new(ErrorCode::NotPaired, "client is not paired"))
                }
                Verdict::Blocked => Err(RpcError::new(ErrorCode::Denied, "this client is blocked")),
                Verdict::AccountNotGranted => Err(RpcError::new(
                    ErrorCode::AccountNotFound,
                    "account not granted to this client",
                )),
            }
        }
    }
}
