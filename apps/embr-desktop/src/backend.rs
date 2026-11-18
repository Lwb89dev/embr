//! The link between the UI and the daemon.
//!
//! The UI never holds keys and never blocks: it reads a cheap [`Snapshot`] and pushes [`Cmd`]s.
//! One worker thread owns the control connection and does all (blocking) calls; a second thread holds
//! an event subscription so the UI wakes up **only** when the daemon says something changed (no
//! polling while the daemon is up). If the daemon is down the worker retries every 1.5 s.
//!
//! The vault password is sent once and not kept; the control *token* the daemon returns is kept in
//! memory only, to re-attach after a dropped connection.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use embr_client::ClientError;
use embr_client::control::ControlClient;
use embr_core::{AccountId, AccountMeta, Pubkey32};
use embr_ipc::ErrorCode;
use embr_ipc::control::{
    ClientView, ControlEvent, DecisionWire, Nip46Status, PendingView, ScopeWire, Settings,
    StatusView, VaultState,
};
use embr_policy::{AuditRecord, Grant};
use serde_json::{Value, json};

/// A command from the UI.
#[derive(Debug, Clone)]
pub enum Cmd {
    /// Re-read everything.
    Refresh,
    /// Unlock with the vault password.
    Unlock(String),
    /// Create the vault.
    CreateVault(String),
    /// Lock now.
    Lock,
    /// Answer a pending request (the view carries the digest that is echoed back).
    Decide {
        view: Box<PendingView>,
        decision: DecisionWire,
        scope: Option<ScopeWire>,
    },
    /// Generate an account.
    AddGenerated(String),
    /// Import an `nsec`/hex key.
    ImportSecret { label: String, secret: String },
    /// Import a NIP-49 backup.
    ImportNcryptsec {
        label: String,
        ncryptsec: String,
        password: String,
    },
    /// Switch the active account.
    SetActive(AccountId),
    /// Rename.
    Rename(AccountId, String),
    /// Delete an account and its key.
    Remove(AccountId),
    /// Export as NIP-49.
    Export {
        id: AccountId,
        vault_password: String,
        export_password: String,
    },
    /// Write an encrypted backup of the vault.
    Backup(String),
    /// Change the vault password.
    ChangePassword { old: String, new: String },
    /// Forget a client.
    RevokeClient(Pubkey32),
    /// Block a client.
    BlockClient(Pubkey32),
    /// Remove one stored permission.
    RevokeGrant(u64),
    /// Save settings.
    SetSettings(Settings),
    /// Create a bunker URI.
    Bunker(AccountId),
    /// Import a nostrconnect URI.
    NostrConnect { uri: String, account: AccountId },
    /// Start the daemon process.
    StartDaemon,
}

/// A short message for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// Text.
    pub text: String,
    /// Error or success.
    pub error: bool,
    /// Increases with every notice so the UI can tell new ones.
    pub seq: u64,
}

/// Everything the UI draws from.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// The daemon could not be reached (reason), or is reachable (`None`).
    pub daemon_down: Option<String>,
    /// Daemon status.
    pub status: Option<StatusView>,
    /// This UI session is authenticated for the control channel.
    pub authed: bool,
    /// Accounts.
    pub accounts: Vec<AccountMeta>,
    /// Active account.
    pub active: Option<AccountId>,
    /// Pending approvals.
    pub pending: Vec<PendingView>,
    /// Paired apps.
    pub clients: Vec<ClientView>,
    /// Stored permissions.
    pub grants: Vec<Grant>,
    /// Settings.
    pub settings: Option<Settings>,
    /// NIP-46 status.
    pub nip46: Option<Nip46Status>,
    /// Recent activity.
    pub log: Vec<AuditRecord>,
    /// Last message.
    pub notice: Option<Notice>,
    /// A freshly created `bunker://` URI (shown once).
    pub bunker_uri: Option<String>,
    /// A freshly exported `ncryptsec` (shown once).
    pub exported: Option<String>,
}

/// Handle used by the UI.
pub struct Backend {
    tx: Sender<Cmd>,
    state: Arc<Mutex<Snapshot>>,
}

impl Backend {
    /// Starts the worker and event threads. `wake` is called whenever the snapshot changed.
    pub fn spawn(
        endpoint: Option<std::path::PathBuf>,
        wake: impl Fn() + Send + Sync + Clone + 'static,
    ) -> Backend {
        let (tx, rx) = mpsc::channel();
        let state = Arc::new(Mutex::new(Snapshot::default()));
        let (tok_tx, tok_rx) = mpsc::channel::<Option<String>>();
        {
            let (tx, wake, endpoint) = (tx.clone(), wake.clone(), endpoint.clone());
            std::thread::spawn(move || event_thread(endpoint, tok_rx, tx, wake));
        }
        {
            let state = state.clone();
            std::thread::spawn(move || worker(endpoint, rx, state, tok_tx, wake));
        }
        let _ = tx.send(Cmd::Refresh);
        Backend { tx, state }
    }

    /// A UI with canned data and no daemon connection (`embr --demo`). Commands are ignored.
    pub fn demo(snapshot: Snapshot) -> Backend {
        let (tx, _rx) = mpsc::channel();
        Backend {
            tx,
            state: Arc::new(Mutex::new(snapshot)),
        }
    }

    /// A copy of the current state.
    pub fn snapshot(&self) -> Snapshot {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sends a command.
    pub fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }
}

fn set<R>(state: &Mutex<Snapshot>, f: impl FnOnce(&mut Snapshot) -> R) -> R {
    f(&mut state.lock().unwrap_or_else(PoisonError::into_inner))
}

fn notice(state: &Mutex<Snapshot>, text: impl Into<String>, error: bool) {
    set(state, |s| {
        let seq = s.notice.as_ref().map_or(1, |n| n.seq + 1);
        s.notice = Some(Notice {
            text: text.into(),
            error,
            seq,
        });
    });
}

fn message(e: &ClientError) -> String {
    match e {
        ClientError::Rpc(r) => r.message.clone(),
        other => other.to_string(),
    }
}

fn is_connection_problem(e: &ClientError) -> bool {
    matches!(
        e,
        ClientError::Connect(_)
            | ClientError::Io(_)
            | ClientError::Codec(_)
            | ClientError::Protocol(_)
    )
}

fn worker(
    endpoint: Option<std::path::PathBuf>,
    rx: Receiver<Cmd>,
    state: Arc<Mutex<Snapshot>>,
    tokens: Sender<Option<String>>,
    wake: impl Fn() + Send + Sync + Clone + 'static,
) {
    let mut client: Option<ControlClient> = None;
    loop {
        // While connected: block until something happens (no polling). While down: retry periodically.
        let cmd = if client.is_some() {
            match rx.recv() {
                Ok(c) => Some(c),
                Err(_) => return,
            }
        } else {
            match rx.recv_timeout(Duration::from_millis(1500)) {
                Ok(c) => Some(c),
                Err(RecvTimeoutError::Timeout) => Some(Cmd::Refresh),
                Err(RecvTimeoutError::Disconnected) => return,
            }
        };
        let Some(cmd) = cmd else { continue };

        if matches!(cmd, Cmd::StartDaemon) {
            start_daemon(&state);
            wake();
            continue;
        }
        if client.is_none() {
            match ControlClient::connect(endpoint.clone()) {
                Ok(c) => {
                    client = Some(c);
                    set(&state, |s| s.daemon_down = None);
                }
                Err(e) => {
                    set(&state, |s| {
                        s.daemon_down = Some(message(&e));
                        s.authed = false;
                        s.status = None;
                    });
                    wake();
                    continue;
                }
            }
        }
        let Some(c) = client.as_mut() else { continue };
        let result = run_cmd(c, &cmd, &state, &tokens);
        let result = result.and_then(|()| refresh(c, &state));
        if let Err(e) = result {
            if is_connection_problem(&e) {
                client = None;
                set(&state, |s| {
                    s.daemon_down = Some(message(&e));
                    s.authed = false;
                });
            } else if matches!(&e, ClientError::Rpc(r) if r.error_code() == Some(ErrorCode::Unauthenticated) && !matches!(cmd, Cmd::Unlock(_) | Cmd::CreateVault(_)))
            {
                set(&state, |s| s.authed = false);
                let _ = tokens.send(None);
                notice(&state, "Session expired: unlock again.", true);
            } else {
                notice(&state, message(&e), true);
            }
        }
        wake();
    }
}

fn start_daemon(state: &Mutex<Snapshot>) {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join(if cfg!(windows) { "embrd.exe" } else { "embrd" }))
        })
        .filter(|p| p.exists())
        .unwrap_or_else(|| "embrd".into());
    match std::process::Command::new(exe)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => notice(state, "Starting the signer daemon…", false),
        Err(e) => notice(state, format!("Cannot start `embrd`: {e}"), true),
    }
}

fn run_cmd(
    c: &mut ControlClient,
    cmd: &Cmd,
    state: &Mutex<Snapshot>,
    tokens: &Sender<Option<String>>,
) -> Result<(), ClientError> {
    let ok = |text: &str| notice(state, text, false);
    match cmd {
        Cmd::Refresh | Cmd::StartDaemon => {}
        Cmd::Unlock(pw) => {
            let t = c.unlock(pw)?;
            set(state, |s| s.authed = true);
            let _ = tokens.send(Some(t));
        }
        Cmd::CreateVault(pw) => {
            let t = c.create_vault(pw)?;
            set(state, |s| s.authed = true);
            let _ = tokens.send(Some(t));
            ok("Vault created. Add or import an identity to get started.");
        }
        Cmd::Lock => {
            c.call("lock", json!({}))?;
            set(state, |s| {
                s.authed = false;
                s.accounts.clear();
                s.pending.clear();
                s.clients.clear();
                s.grants.clear();
                s.bunker_uri = None;
                s.exported = None;
            });
            let _ = tokens.send(None);
        }
        Cmd::Decide {
            view,
            decision,
            scope,
        } => {
            c.decide(view, *decision, *scope)?;
        }
        Cmd::AddGenerated(label) => {
            c.call("add_generated", json!({"label": label}))?;
            ok("Identity created.");
        }
        Cmd::ImportSecret { label, secret } => {
            c.call("import_secret", json!({"label": label, "secret": secret}))?;
            ok("Key imported. It is recorded as handled insecurely (it was pasted as text).");
        }
        Cmd::ImportNcryptsec {
            label,
            ncryptsec,
            password,
        } => {
            c.call(
                "import_ncryptsec",
                json!({"label": label, "ncryptsec": ncryptsec, "password": password}),
            )?;
            ok("Encrypted backup imported.");
        }
        Cmd::SetActive(id) => {
            c.call("set_active", json!({"id": id.to_string()}))?;
        }
        Cmd::Rename(id, label) => {
            c.call("set_label", json!({"id": id.to_string(), "label": label}))?;
        }
        Cmd::Remove(id) => {
            c.call(
                "remove_account",
                json!({"id": id.to_string(), "confirm": true}),
            )?;
            ok("Account and its key were deleted.");
        }
        Cmd::Export {
            id,
            vault_password,
            export_password,
        } => {
            let v = c.call(
                "export_ncryptsec",
                json!({"id": id.to_string(), "vault_password": vault_password, "export_password": export_password, "log_n": 18}),
            )?;
            let enc = v
                .get("ncryptsec")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            set(state, |s| s.exported = Some(enc));
        }
        Cmd::Backup(path) => {
            c.call("export_backup", json!({"dest": path}))?;
            ok("Encrypted backup written. It is protected by your CURRENT vault password.");
        }
        Cmd::ChangePassword { old, new } => {
            c.call("change_password", json!({"old": old, "new": new}))?;
            ok("Password changed and the vault key rotated.");
        }
        Cmd::RevokeClient(k) => {
            c.call("revoke_client", json!({"key": k.to_string()}))?;
        }
        Cmd::BlockClient(k) => {
            c.call("block_client", json!({"key": k.to_string()}))?;
        }
        Cmd::RevokeGrant(id) => {
            c.call("revoke_grant", json!({"id": id}))?;
        }
        Cmd::SetSettings(s) => {
            c.call(
                "set_settings",
                serde_json::to_value(s).unwrap_or(Value::Null),
            )?;
            ok("Settings saved.");
        }
        Cmd::Bunker(id) => {
            let v = c.call("nip46_bunker", json!({"account": id.to_string()}))?;
            let uri = v
                .get("uri")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            set(state, |s| s.bunker_uri = Some(uri));
        }
        Cmd::NostrConnect { uri, account } => {
            c.call(
                "nip46_connect",
                json!({"uri": uri, "account": account.to_string()}),
            )?;
            ok(
                "Pending approval: review it under Approvals. Its relays are contacted only if you approve.",
            );
        }
    }
    Ok(())
}

fn refresh(c: &mut ControlClient, state: &Mutex<Snapshot>) -> Result<(), ClientError> {
    let status = c.status()?;
    let unlocked = status.vault == VaultState::Unlocked;
    set(state, |s| {
        s.status = Some(status);
        if !unlocked {
            s.authed = false;
        }
    });
    if !(unlocked && set(state, |s| s.authed)) {
        return Ok(());
    }
    let acc = c.call("list_accounts", json!({}))?;
    let accounts: Vec<AccountMeta> = acc
        .get("accounts")
        .cloned()
        .and_then(|a| serde_json::from_value(a).ok())
        .unwrap_or_default();
    let active = acc
        .get("active")
        .cloned()
        .and_then(|a| serde_json::from_value(a).ok());
    let pending = c.pending()?;
    let clients: Vec<ClientView> =
        serde_json::from_value(c.call("list_clients", json!({}))?).unwrap_or_default();
    let grants: Vec<Grant> =
        serde_json::from_value(c.call("list_grants", json!({}))?).unwrap_or_default();
    let settings: Option<Settings> =
        serde_json::from_value(c.call("get_settings", json!({}))?).ok();
    let nip46: Option<Nip46Status> =
        serde_json::from_value(c.call("nip46_status", json!({}))?).ok();
    let log: Vec<AuditRecord> =
        serde_json::from_value(c.call("recent_log", json!({"limit": 60}))?).unwrap_or_default();
    set(state, |s| {
        s.accounts = accounts;
        s.active = active;
        s.pending = pending;
        s.clients = clients;
        s.grants = grants;
        s.settings = settings;
        s.nip46 = nip46;
        s.log = log;
    });
    Ok(())
}

/// Holds a subscription so the UI is woken by daemon events instead of polling.
fn event_thread(
    endpoint: Option<std::path::PathBuf>,
    tokens: Receiver<Option<String>>,
    cmds: Sender<Cmd>,
    wake: impl Fn() + Send + Sync + 'static,
) {
    let mut token: Option<String> = None;
    loop {
        let Some(t) = token.clone() else {
            match tokens.recv() {
                Ok(t) => token = t,
                Err(_) => return,
            }
            continue;
        };
        if let Ok(mut c) = ControlClient::connect(endpoint.clone()) {
            if c.authenticate(&t).is_ok() && c.subscribe().is_ok() {
                loop {
                    match c.next_event() {
                        Ok(Some(ev)) => {
                            let locked = matches!(ev, ControlEvent::Locked);
                            let _ = cmds.send(Cmd::Refresh);
                            wake();
                            if locked {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(_) => break,
                    }
                }
            } else {
                token = None; // the token is no longer valid
            }
        }
        // Wait a moment (or for a new token) before reconnecting.
        match tokens.recv_timeout(Duration::from_millis(1500)) {
            Ok(t) => token = t,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The backend against a **real daemon** on a real socket: everything the GUI does goes through here.
#[cfg(all(test, unix))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use embr_client::{ConnectOptions, SignerClient};
    use embr_crypto::Identity;
    use embr_ipc::control::PendingKind;
    use embr_vault::KdfParams;
    use std::time::Instant;

    const PW: &str = "correct horse battery staple";

    struct Rig {
        _tmp: tempfile::TempDir,
        rt: tokio::runtime::Runtime,
        daemon: Option<embrd::DaemonHandle>,
        cfg: embrd::DaemonConfig,
        backend: Backend,
    }

    impl Rig {
        /// A backend pointed at a daemon that is **not running yet**.
        fn stopped() -> Rig {
            let tmp = tempfile::Builder::new().prefix("g").tempdir().unwrap();
            let run = tmp.path().join("r");
            let mut cfg = embrd::DaemonConfig::from_environment();
            cfg.data_dir = tmp.path().join("d");
            cfg.runtime_dir = run.clone();
            cfg.signer_socket = run.join("signer.sock");
            cfg.control_socket = run.join("control.sock");
            cfg.kdf = KdfParams::MINIMUM;
            cfg.harden = false;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let backend = Backend::spawn(Some(cfg.control_socket.clone()), || {});
            Rig {
                _tmp: tmp,
                rt,
                daemon: None,
                cfg,
                backend,
            }
        }

        fn start(&mut self) {
            self.daemon = Some(self.rt.block_on(embrd::start(self.cfg.clone())).unwrap());
        }

        fn new() -> Rig {
            let mut rig = Rig::stopped();
            rig.start();
            rig
        }

        /// Polls the snapshot until `f` holds.
        fn wait(&self, what: &str, f: impl Fn(&Snapshot) -> bool) -> Snapshot {
            let start = Instant::now();
            loop {
                let s = self.backend.snapshot();
                if f(&s) {
                    return s;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(15),
                    "timed out waiting for: {what}; last notice {:?}, down {:?}",
                    s.notice,
                    s.daemon_down
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn unlocked(s: &Snapshot) -> bool {
            s.authed
                && s.status
                    .as_ref()
                    .is_some_and(|x| x.vault == VaultState::Unlocked)
        }

        /// Creates the vault and one account through the backend, as the GUI would.
        fn with_account(&self) -> AccountMeta {
            self.backend.send(Cmd::CreateVault(PW.into()));
            self.wait("vault created", Self::unlocked);
            self.backend.send(Cmd::AddGenerated("Personal".into()));
            let s = self.wait("account listed", |s| s.accounts.len() == 1);
            s.accounts[0].clone()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            if let Some(d) = self.daemon.take() {
                self.rt.block_on(d.shutdown());
            }
        }
    }

    #[test]
    fn a_new_vault_is_created_unlocked_and_gets_an_account() {
        let rig = Rig::new();
        let s = rig.wait("daemon reachable", |s| s.status.is_some());
        assert_eq!(s.status.unwrap().vault, VaultState::Missing);
        assert!(!s.authed && s.daemon_down.is_none());

        let a = rig.with_account();
        let s = rig.backend.snapshot();
        assert_eq!(a.label, "Personal");
        assert_eq!(s.active, Some(a.id));
        assert!(a.npub.starts_with("npub1"));
    }

    #[test]
    fn locking_clears_what_the_ui_was_holding_and_a_wrong_password_does_not_unlock() {
        let rig = Rig::new();
        rig.with_account();
        rig.backend.send(Cmd::Lock);
        let s = rig.wait("locked", |s| {
            !s.authed
                && s.status
                    .as_ref()
                    .is_some_and(|x| x.vault == VaultState::Locked)
        });
        assert!(
            s.accounts.is_empty(),
            "account list must not survive a lock"
        );

        rig.backend.send(Cmd::Unlock("wrong password".into()));
        let s = rig.wait("error notice", |s| {
            s.notice.as_ref().is_some_and(|n| n.error)
        });
        assert!(!s.authed);
        assert!(s.accounts.is_empty());

        rig.backend.send(Cmd::Unlock(PW.into()));
        let s = rig.wait("unlocked again", |s| {
            Rig::unlocked(s) && s.accounts.len() == 1
        });
        assert_eq!(s.accounts[0].label, "Personal");
    }

    #[test]
    fn an_app_asks_to_pair_the_user_approves_and_it_can_then_sign() {
        let rig = Rig::new();
        let account = rig.with_account();

        // An SDK client (on its own thread: its calls block until the user answers).
        let signer = rig.cfg.signer_socket.clone();
        let app = std::thread::spawn(move || {
            let id = Identity::generate();
            let mut o = ConnectOptions::new("Test App");
            o.endpoint = Some(signer);
            o.read_timeout = Some(Duration::from_secs(20));
            let mut c = SignerClient::connect(&id, o).unwrap();
            let pk = c.get_public_key(None).unwrap();
            let signed = c
                .sign_event(
                    &serde_json::json!({"kind": 1, "content": "hello from the test"}),
                    None,
                )
                .unwrap();
            (pk, signed)
        });

        // The pairing request shows up in the snapshot; answer it the way the Approve button does.
        let s = rig.wait("pairing request", |s| !s.pending.is_empty());
        let view = s.pending[0].clone();
        assert_eq!(view.kind, PendingKind::Pair);
        assert_eq!(view.client.name, "Test App");
        rig.backend.send(Cmd::Decide {
            view: Box::new(view),
            decision: DecisionWire::Pair {
                account: account.id,
            },
            scope: None,
        });

        // Then the signing request, which must show the exact event.
        let s = rig.wait("signing request", |s| {
            s.pending.iter().any(|p| p.kind == PendingKind::Operation)
        });
        let view = s
            .pending
            .iter()
            .find(|p| p.kind == PendingKind::Operation)
            .unwrap()
            .clone();
        let ev = view.event.clone().expect("the preview carries the event");
        assert_eq!((ev.kind, ev.content.as_str()), (1, "hello from the test"));
        rig.backend.send(Cmd::Decide {
            view: Box::new(view),
            decision: DecisionWire::AllowOnce,
            scope: None,
        });

        let (pk, signed) = app.join().unwrap();
        assert_eq!(pk, account.pubkey_hex);
        assert_eq!(signed.pubkey.to_hex(), account.pubkey_hex);
        assert_eq!(signed.content, "hello from the test");
        assert!(signed.verify().is_ok(), "the signature must verify");

        // …and it is listed as a paired app, and the log recorded it (metadata only).
        let s = rig.wait("client listed and the signing logged", |s| {
            s.pending.is_empty()
                && !s.clients.is_empty()
                && s.log.iter().any(|r| r.action == "sign_event")
        });

        assert_eq!(s.clients[0].record.name, "Test App");
        let dump = format!("{:?}", s.log);
        assert!(
            !dump.contains("hello from the test"),
            "the log must not hold message content"
        );
        assert!(s.pending.is_empty());
    }

    #[test]
    fn a_missing_daemon_is_reported_and_picked_up_when_it_appears() {
        let mut rig = Rig::stopped();
        let s = rig.wait("reported down", |s| s.daemon_down.is_some());
        assert!(s.status.is_none() && !s.authed);

        // The worker retries on its own; no user action is needed once the daemon is there.
        rig.start();
        let s = rig.wait("daemon found", |s| {
            s.daemon_down.is_none() && s.status.is_some()
        });
        assert_eq!(s.status.unwrap().vault, VaultState::Missing);
    }
}
