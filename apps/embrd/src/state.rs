//! Shared daemon state and the primitives that mutate it.
//!
//! One `std::sync::Mutex<Inner>` guards everything that must change atomically together: the
//! vault slot, the policy engine, the pending-approval queue and the control tokens. The lock is
//! never held across an `.await`; long operations (Argon2id) take the vault *out* of its slot,
//! run on a blocking thread, and put it back (see [`Shared::with_vault_blocking`]).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use embr_core::{AccountId, AccountMeta, Pubkey32};
use embr_crypto::Limits;
use embr_ipc::control::{ControlEvent, PendingView, Settings, StatusView, VaultState};
use embr_ipc::{ErrorCode, RpcError};
use embr_policy::{AuditOutcome, AuditRecord, Engine, RateLimiter, SessionId};
use embr_vault::{KdfParams, Vault, VaultError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, broadcast, oneshot};
use tokio_util::sync::CancellationToken;

use crate::audit::Audit;
use crate::canonical::Canonical;

/// Name of the policy blob inside the vault.
pub const POLICY_BLOB: &str = "policy/v1";
/// Name of the settings blob inside the vault.
pub const SETTINGS_BLOB: &str = "settings/v1";

/// Resource limits of the daemon (all overridable in tests).
#[derive(Clone, Debug)]
pub struct DaemonLimits {
    /// Pending approvals per client.
    pub pending_per_client: usize,
    /// Pending approvals in total.
    pub pending_total: usize,
    /// Concurrent connections that have not finished the handshake.
    pub max_unauthenticated: usize,
    /// Concurrent connections in total (per socket kind).
    pub max_connections: usize,
    /// Idle time after which a client session is closed.
    pub idle_secs: u64,
    /// Handshake deadline.
    pub handshake_secs: u64,
    /// Burst size of the per-client rate limit.
    pub rate_burst: u32,
    /// Sustained requests per second per client.
    pub rate_per_sec: u32,
    /// Default time a request waits for the user.
    pub default_timeout_ms: u64,
    /// Maximum time a client may ask a request to wait.
    pub max_timeout_ms: u64,
    /// Consecutive wrong passwords before throttling starts.
    pub unlock_free_attempts: u32,
}

impl Default for DaemonLimits {
    fn default() -> Self {
        Self {
            pending_per_client: 16,
            pending_total: 64,
            max_unauthenticated: 8,
            max_connections: 64,
            idle_secs: 15 * 60,
            handshake_secs: embr_ipc::HANDSHAKE_TIMEOUT_SECS,
            rate_burst: 20,
            rate_per_sec: 5,
            default_timeout_ms: embr_ipc::DEFAULT_TIMEOUT_MS,
            max_timeout_ms: embr_ipc::MAX_TIMEOUT_MS,
            unlock_free_attempts: 5,
        }
    }
}

/// Daemon configuration.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Directory holding the vault and the audit log.
    pub data_dir: PathBuf,
    /// Directory for the sockets and the instance lock.
    pub runtime_dir: PathBuf,
    /// Client-API socket.
    pub signer_socket: PathBuf,
    /// Control socket.
    pub control_socket: PathBuf,
    /// Argon2id cost for new vaults / password changes.
    pub kdf: KdfParams,
    /// Apply process hardening (core dumps off, …).
    pub harden: bool,
    /// Resource limits.
    pub limits: DaemonLimits,
}

impl DaemonConfig {
    /// Defaults from the environment and the platform conventions.
    pub fn from_environment() -> Self {
        let runtime_dir = embr_platform::paths::runtime_dir();
        Self {
            data_dir: embr_platform::paths::data_dir(),
            signer_socket: embr_platform::paths::signer_socket(),
            control_socket: embr_platform::paths::control_socket(),
            runtime_dir,
            kdf: KdfParams::DEFAULT,
            harden: true,
            limits: DaemonLimits::default(),
        }
    }

    /// Path of the vault file.
    pub fn vault_path(&self) -> PathBuf {
        self.data_dir.join("vault.embr")
    }
}

/// Where the vault is.
pub enum VaultSlot {
    /// No vault file exists yet.
    Missing,
    /// The vault (locked or unlocked).
    Present(Box<Vault>),
    /// Temporarily taken out for a long (KDF) operation.
    Busy,
}

/// What a waiting client gets when its request is resolved.
pub type Done = Result<Value, RpcError>;

/// How a resolved pairing is reported to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyKind {
    /// `connect`: `{ "paired": true, "account": <hex> }`.
    Connect,
    /// `get_public_key`: the account's public key as a string.
    GetPublicKey,
    /// An operation: the operation's result.
    Operation,
}

/// A request waiting for the user.
pub struct PendingEntry {
    /// What the user sees.
    pub view: PendingView,
    /// The stored canonical request that will be executed.
    pub canonical: Canonical,
    /// The policy request (operations only).
    pub request: Option<embr_policy::Request>,
    /// Requesting session.
    pub session: SessionId,
    /// Requesting client.
    pub client: Pubkey32,
    /// Self-declared client label (sanitised).
    pub client_name: String,
    /// Target account (operations only).
    pub account: Option<AccountId>,
    /// Reply shape.
    pub reply: ReplyKind,
    /// Where to send the result.
    pub tx: Option<oneshot::Sender<Done>>,
}

/// A control token (only a hash is kept).
pub struct TokenRec {
    hash: [u8; 32],
    issued: Instant,
}

/// An open client session.
pub struct SessionRec {
    /// Client key.
    pub client: Pubkey32,
}

/// Everything guarded by the state mutex.
pub struct Inner {
    /// The vault.
    pub vault: VaultSlot,
    /// Authorization engine (loaded at unlock, emptied at lock).
    pub policy: Engine,
    /// Settings (loaded at unlock, defaults while locked).
    pub settings: Settings,
    /// Pending approvals.
    pub pending: BTreeMap<u64, PendingEntry>,
    next_pending: u64,
    tokens: Vec<TokenRec>,
    /// Incremented on every lock; control connections authenticated in an older epoch lose access.
    pub lock_epoch: u64,
    /// Last *user* activity (control channel), for idle auto-lock.
    pub last_activity: Instant,
    fail_count: u32,
    block_until: Option<Instant>,
    /// Per-client rate limiter.
    pub limiter: RateLimiter<Pubkey32>,
    audit: Audit,
    /// Open client sessions.
    pub sessions: BTreeMap<SessionId, SessionRec>,
}

/// Shared handle.
pub struct Shared {
    /// Configuration.
    pub cfg: DaemonConfig,
    inner: Mutex<Inner>,
    events: broadcast::Sender<ControlEvent>,
    /// Wakes the idle-lock task when the deadline may have changed.
    pub activity: Notify,
    /// Cancelled on shutdown.
    pub shutdown: CancellationToken,
    next_session: AtomicU64,
    /// Connections that have not finished the handshake.
    pub unauth_conns: AtomicUsize,
    /// Open client-API connections.
    pub client_conns: AtomicUsize,
    /// Open control connections.
    pub control_conns: AtomicUsize,
    started: Instant,
}

/// Current Unix time in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Maps vault errors to protocol errors.
pub fn map_vault_err(e: VaultError) -> RpcError {
    match e {
        VaultError::Locked => RpcError::new(ErrorCode::VaultLocked, "vault is locked"),
        VaultError::WrongPasswordOrCorrupt => RpcError::new(
            ErrorCode::Unauthenticated,
            "wrong password or corrupted vault",
        ),
        VaultError::AccountNotFound => {
            RpcError::new(ErrorCode::AccountNotFound, "account not found")
        }
        VaultError::Io(_) | VaultError::Rng => RpcError::new(ErrorCode::Internal, "storage error"),
        other => RpcError::new(ErrorCode::InvalidParams, other.to_string()),
    }
}

impl Shared {
    /// Builds the shared state, opening an existing vault (locked) if there is one.
    pub fn new(cfg: DaemonConfig) -> Arc<Self> {
        let vault = match Vault::open(cfg.vault_path()) {
            Ok(v) => VaultSlot::Present(Box::new(v)),
            Err(_) => VaultSlot::Missing,
        };
        let limits = cfg.limits.clone();
        let audit = Audit::open(cfg.data_dir.join("audit.jsonl"));
        let (events, _) = broadcast::channel(256);
        Arc::new(Shared {
            inner: Mutex::new(Inner {
                vault,
                policy: Engine::new(),
                settings: Settings::default(),
                pending: BTreeMap::new(),
                next_pending: 1,
                tokens: Vec::new(),
                lock_epoch: 0,
                last_activity: Instant::now(),
                fail_count: 0,
                block_until: None,
                limiter: RateLimiter::new(limits.rate_burst, limits.rate_per_sec),
                audit,
                sessions: BTreeMap::new(),
            }),
            cfg,
            events,
            activity: Notify::new(),
            shutdown: CancellationToken::new(),
            next_session: AtomicU64::new(1),
            unauth_conns: AtomicUsize::new(0),
            client_conns: AtomicUsize::new(0),
            control_conns: AtomicUsize::new(0),
            started: Instant::now(),
        })
    }

    /// Locks the state (recovering from poisoning: a panicking task must not brick the daemon).
    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new session id.
    pub fn new_session(&self) -> SessionId {
        SessionId(self.next_session.fetch_add(1, Ordering::Relaxed))
    }

    /// Subscribes to control events.
    pub fn subscribe(&self) -> broadcast::Receiver<ControlEvent> {
        self.events.subscribe()
    }

    /// Broadcasts a control event (ignored if nobody listens).
    pub fn emit(&self, ev: ControlEvent) {
        let _ = self.events.send(ev);
    }

    /// Seconds since the daemon started.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Runs a long vault operation on a blocking thread without holding the state lock.
    /// While it runs, the vault slot is [`VaultSlot::Busy`] and other requests see `busy`.
    pub async fn with_vault_blocking<R: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut Vault) -> R + Send + 'static,
    ) -> Result<R, RpcError> {
        let mut vault = {
            let mut g = self.lock();
            match std::mem::replace(&mut g.vault, VaultSlot::Busy) {
                VaultSlot::Present(v) => v,
                VaultSlot::Missing => {
                    g.vault = VaultSlot::Missing;
                    return Err(RpcError::new(
                        ErrorCode::InvalidRequest,
                        "no vault exists yet; create one first",
                    ));
                }
                VaultSlot::Busy => {
                    g.vault = VaultSlot::Busy;
                    return Err(RpcError::new(
                        ErrorCode::Busy,
                        "another vault operation is in progress",
                    ));
                }
            }
        };
        let path = self.cfg.vault_path();
        match tokio::task::spawn_blocking(move || {
            let r = f(&mut vault);
            (vault, r)
        })
        .await
        {
            Ok((vault, r)) => {
                self.lock().vault = VaultSlot::Present(vault);
                Ok(r)
            }
            Err(_) => {
                // The task panicked: reopen the file (locked) rather than lose the slot.
                self.lock().vault = Vault::open(path)
                    .map_or(VaultSlot::Missing, |v| VaultSlot::Present(Box::new(v)));
                Err(RpcError::new(ErrorCode::Internal, "internal error"))
            }
        }
    }

    /// Status snapshot (no secrets, no account data).
    pub fn status(&self) -> StatusView {
        let g = self.lock();
        g.status_view()
    }
}

impl Inner {
    /// Vault state for status reporting.
    pub fn vault_state(&self) -> VaultState {
        match &self.vault {
            VaultSlot::Missing => VaultState::Missing,
            VaultSlot::Present(v) if v.is_unlocked() => VaultState::Unlocked,
            VaultSlot::Present(_) => VaultState::Locked,
            VaultSlot::Busy => VaultState::Locked,
        }
    }

    /// The unlocked vault, or the right error.
    pub fn vault_ref(&self) -> Result<&Vault, RpcError> {
        match &self.vault {
            VaultSlot::Present(v) if v.is_unlocked() => Ok(v),
            VaultSlot::Present(_) => Err(RpcError::new(ErrorCode::VaultLocked, "vault is locked")),
            VaultSlot::Missing => Err(RpcError::new(ErrorCode::VaultLocked, "no vault exists yet")),
            VaultSlot::Busy => Err(RpcError::new(ErrorCode::Busy, "vault is busy; retry")),
        }
    }

    /// The unlocked vault, mutably.
    pub fn vault_mut(&mut self) -> Result<&mut Vault, RpcError> {
        match &mut self.vault {
            VaultSlot::Present(v) if v.is_unlocked() => Ok(v),
            VaultSlot::Present(_) => Err(RpcError::new(ErrorCode::VaultLocked, "vault is locked")),
            VaultSlot::Missing => Err(RpcError::new(ErrorCode::VaultLocked, "no vault exists yet")),
            VaultSlot::Busy => Err(RpcError::new(ErrorCode::Busy, "vault is busy; retry")),
        }
    }

    /// Status snapshot.
    pub fn status_view(&self) -> StatusView {
        let state = self.vault_state();
        let timeout = self.settings.lock_timeout_secs;
        let locks_in = (state == VaultState::Unlocked && timeout > 0)
            .then(|| timeout.saturating_sub(self.last_activity.elapsed().as_secs()));
        StatusView {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            vault: state,
            pending: self.pending.len(),
            lock_timeout_secs: timeout,
            locks_in_secs: locks_in,
            remote_signing_enabled: self.settings.remote_signing_enabled,
        }
    }

    /// Records user activity (resets the idle-lock deadline).
    pub fn touch_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Appends to the audit log.
    pub fn audit(&mut self, rec: &AuditRecord) {
        self.audit.record(rec);
    }

    /// Reads recent audit records.
    pub fn recent_audit(&self, limit: usize) -> Vec<AuditRecord> {
        self.audit.recent(limit)
    }

    /// An administrative audit record.
    pub fn audit_admin(&mut self, action: &str, note: Option<&str>) {
        self.audit.record(&AuditRecord {
            ts: now_secs(),
            via: "control".into(),
            client: None,
            client_name: None,
            account: None,
            action: action.to_owned(),
            kind: None,
            outcome: AuditOutcome::Admin,
            grant: None,
            note: note.map(str::to_owned),
        });
    }

    /// Persists the policy into the vault. Failures are returned so callers can surface them.
    pub fn persist_policy(&mut self) -> Result<(), RpcError> {
        let json = self.policy.to_json();
        let Inner { vault, .. } = self;
        match vault {
            VaultSlot::Present(v) if v.is_unlocked() => {
                v.set_blob(POLICY_BLOB, Some(&json)).map_err(map_vault_err)
            }
            _ => Err(RpcError::new(ErrorCode::VaultLocked, "vault is locked")),
        }
    }

    /// Persists the settings into the vault.
    pub fn persist_settings(&mut self) -> Result<(), RpcError> {
        let json = serde_json::to_vec(&self.settings)
            .map_err(|_| RpcError::new(ErrorCode::Internal, "serialise settings"))?;
        match &mut self.vault {
            VaultSlot::Present(v) if v.is_unlocked() => v
                .set_blob(SETTINGS_BLOB, Some(&json))
                .map_err(map_vault_err),
            _ => Err(RpcError::new(ErrorCode::VaultLocked, "vault is locked")),
        }
    }

    /// Accounts of the vault, if unlocked.
    pub fn accounts(&self) -> Result<Vec<AccountMeta>, RpcError> {
        self.vault_ref()?.list_accounts().map_err(map_vault_err)
    }

    // ===== pending queue ================================================================

    /// Number of pending requests of `client`.
    pub fn pending_of(&self, client: &Pubkey32) -> usize {
        self.pending
            .values()
            .filter(|p| &p.client == client)
            .count()
    }

    /// Allocates the next pending id.
    pub fn next_pending_id(&mut self) -> u64 {
        let id = self.next_pending;
        self.next_pending += 1;
        id
    }

    /// Resolves and removes a pending request, delivering `result` to its waiter. Returns `false`
    /// if it was already gone.
    pub fn resolve(
        &mut self,
        shared: &Shared,
        id: u64,
        result: Done,
        reason: &str,
        outcome: AuditOutcome,
    ) -> bool {
        let Some(entry) = self.pending.remove(&id) else {
            return false;
        };
        self.finish_entry(shared, id, entry, result, reason, outcome);
        true
    }

    /// Completes an entry that has already been taken out of the queue: delivers the result,
    /// writes the audit record and notifies subscribers.
    pub fn finish_entry(
        &mut self,
        shared: &Shared,
        id: u64,
        mut entry: PendingEntry,
        result: Done,
        reason: &str,
        outcome: AuditOutcome,
    ) {
        if let Some(tx) = entry.tx.take() {
            let _ = tx.send(result);
        }
        self.audit.record(&AuditRecord {
            ts: now_secs(),
            via: entry.view.client.via.clone(),
            client: Some(entry.client),
            client_name: Some(entry.client_name.clone()),
            account: entry.account,
            action: entry
                .view
                .operation
                .clone()
                .unwrap_or_else(|| "pair".into()),
            kind: entry.view.event.as_ref().map(|e| e.kind),
            outcome,
            grant: None,
            note: Some(reason.to_owned()),
        });
        shared.emit(ControlEvent::PendingRemoved {
            id,
            reason: reason.to_owned(),
        });
    }

    /// Cancels every pending request matching `pred`.
    pub fn cancel_pending_where(
        &mut self,
        shared: &Shared,
        why: &str,
        pred: impl Fn(&PendingEntry) -> bool,
    ) {
        let ids: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, e)| pred(e))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.resolve(
                shared,
                id,
                Err(RpcError::new(ErrorCode::Cancelled, why)),
                "cancelled",
                AuditOutcome::Cancelled,
            );
        }
    }

    /// Cancels every pending request (vault locked, shutdown…).
    pub fn cancel_all_pending(&mut self, shared: &Shared, why: &str) {
        let ids: Vec<u64> = self.pending.keys().copied().collect();
        for id in ids {
            self.resolve(
                shared,
                id,
                Err(RpcError::new(ErrorCode::Cancelled, why)),
                "cancelled",
                AuditOutcome::Cancelled,
            );
        }
    }

    // ===== control tokens ===============================================================

    /// Issues a control token (valid until the vault locks or 12 hours pass).
    pub fn issue_token(&mut self) -> Result<String, RpcError> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|_| RpcError::new(ErrorCode::Internal, "rng failure"))?;
        let token = hex::encode(raw);
        self.tokens
            .retain(|t| t.issued.elapsed() < Duration::from_secs(12 * 3600));
        if self.tokens.len() >= 16 {
            self.tokens.remove(0);
        }
        self.tokens.push(TokenRec {
            hash: Sha256::digest(token.as_bytes()).into(),
            issued: Instant::now(),
        });
        Ok(token)
    }

    /// Checks a control token.
    pub fn token_valid(&self, token: &str) -> bool {
        let h: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.tokens
            .iter()
            .any(|t| t.hash == h && t.issued.elapsed() < Duration::from_secs(12 * 3600))
    }

    // ===== unlock throttling ============================================================

    /// `Err(seconds)` if unlock attempts are currently throttled.
    pub fn unlock_allowed(&self) -> Result<(), u64> {
        match self.block_until {
            Some(t) if t > Instant::now() => Err((t - Instant::now()).as_secs() + 1),
            _ => Ok(()),
        }
    }

    /// Records a failed unlock; after `free` consecutive failures the delay doubles up to 5 min.
    pub fn note_unlock_failure(&mut self, free: u32) {
        self.fail_count += 1;
        if self.fail_count > free {
            let exp = (self.fail_count - free).min(9);
            self.block_until = Some(Instant::now() + Duration::from_secs((1u64 << exp).min(300)));
        }
    }

    /// Records a successful unlock.
    pub fn note_unlock_success(&mut self) {
        self.fail_count = 0;
        self.block_until = None;
    }
}

impl Shared {
    /// Locks the vault now: wipes keys, drops the policy and tokens, cancels pending approvals.
    pub fn lock_now(&self, why: &str) {
        let mut g = self.lock();
        let was_unlocked = matches!(&g.vault, VaultSlot::Present(v) if v.is_unlocked());
        if let VaultSlot::Present(v) = &mut g.vault {
            v.lock();
        }
        g.cancel_all_pending(self, "the vault was locked");
        g.policy = Engine::new();
        g.settings = Settings::default();
        g.tokens.clear();
        g.lock_epoch += 1;
        self.activity.notify_one();
        if was_unlocked {
            g.audit_admin("lock", Some(why));
            drop(g);
            self.emit(ControlEvent::Locked);
        }
    }

    /// Default request limits for crypto operations.
    pub fn crypto_limits(&self) -> Limits {
        Limits::default()
    }
}
