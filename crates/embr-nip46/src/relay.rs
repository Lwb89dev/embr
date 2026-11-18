//! A small, event-driven Nostr relay client for NIP-46.
//!
//! Deliberately minimal (no database, no gossip, no discovery): per relay one task that
//! connects, authenticates if asked (NIP-42), subscribes to kind-24133 events `p`-tagged with the
//! signer's transport keys, forwards events, publishes responses, and reconnects with exponential
//! backoff. There are **no timers that poll**: tasks wake on socket data, commands, a 30 s
//! keep-alive ping and the backoff delay of a failed connection.
//!
//! Security notes
//! * Relays are untrusted: anything they send is validated by the caller before use.
//! * `wss://` uses rustls (ring) with the bundled Mozilla roots; plain `ws://` is accepted only for
//!   loopback hosts (enforced by [`crate::uri::validate_relay`], re-checked here).
//! * Inbound messages are capped at 1 MiB.
//! * Nothing here starts unless the daemon constructs a [`Pool`], i.e. unless remote signing was
//!   enabled and relays configured by the user.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use embr_crypto::Event;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::uri::validate_relay;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(30);
const DEAD_AFTER: Duration = Duration::from_secs(90);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_MESSAGE: usize = 1024 * 1024;
const SUB_ID: &str = "embr-nip46";

/// An event received from a relay.
#[derive(Clone, Debug)]
pub struct Incoming {
    /// The (unverified!) event.
    pub event: Event,
    /// Relay it came from.
    pub relay: String,
}

/// Connection state of one relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayState {
    /// Trying to connect.
    Connecting,
    /// Connected and subscribed.
    Connected,
    /// Last attempt failed (reason) — will retry with backoff.
    Failed(String),
}

/// Status of one relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayStatus {
    /// Relay URL.
    pub url: String,
    /// State.
    pub state: RelayState,
}

/// Produces NIP-42 `AUTH` events when a relay asks for authentication. It signs with a *transport*
/// key (never a user key).
pub trait AuthSigner: Send + Sync + 'static {
    /// Returns a signed kind-22242 event answering `challenge` for `relay_url`, if possible.
    fn sign_auth(&self, relay_url: &str, challenge: &str) -> Option<Event>;
}

enum Cmd {
    Publish {
        id: String,
        json: String,
        ack: oneshot::Sender<Result<(), String>>,
    },
}

struct RelayHandle {
    cmds: mpsc::Sender<Cmd>,
    cancel: CancellationToken,
}

/// A set of relay connections.
pub struct Pool {
    relays: Mutex<HashMap<String, RelayHandle>>,
    status: Arc<Mutex<BTreeMap<String, RelayStatus>>>,
    pubkeys: watch::Sender<Vec<String>>,
    events_tx: mpsc::Sender<Incoming>,
    auth: Arc<dyn AuthSigner>,
    cancel: CancellationToken,
    /// `None` = the bundled Mozilla roots (always, outside tests).
    tls: Option<Arc<rustls::ClientConfig>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Pool {
    /// Creates the pool and the channel inbound events arrive on. Nothing connects until
    /// [`Pool::set_relays`] is called.
    pub fn new(
        auth: Arc<dyn AuthSigner>,
        cancel: CancellationToken,
    ) -> (Arc<Pool>, mpsc::Receiver<Incoming>) {
        Self::with_tls(auth, cancel, None)
    }

    /// Like [`Pool::new`], but a `wss://` relay is verified against `roots` **instead of** the bundled
    /// Mozilla roots. Exists only so tests can talk TLS to an in-process relay with a throw-away
    /// certificate; the `testing` feature is never enabled in the daemon, the CLI or the desktop app.
    #[cfg(feature = "testing")]
    pub fn new_trusting(
        auth: Arc<dyn AuthSigner>,
        cancel: CancellationToken,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<(Arc<Pool>, mpsc::Receiver<Incoming>), String> {
        Ok(Self::with_tls(auth, cancel, Some(trusting_config(roots)?)))
    }

    pub(crate) fn with_tls(
        auth: Arc<dyn AuthSigner>,
        cancel: CancellationToken,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> (Arc<Pool>, mpsc::Receiver<Incoming>) {
        let (events_tx, events_rx) = mpsc::channel(512);
        let (pubkeys, _) = watch::channel(Vec::new());
        let pool = Arc::new(Pool {
            relays: Mutex::new(HashMap::new()),
            status: Arc::default(),
            pubkeys,
            events_tx,
            auth,
            cancel,
            tls,
        });
        (pool, events_rx)
    }

    /// Replaces the relay set: new URLs start connecting, removed URLs are disconnected.
    /// Invalid URLs are ignored.
    pub fn set_relays(self: &Arc<Self>, urls: &[String]) {
        let wanted: Vec<String> = urls.iter().filter_map(|u| validate_relay(u).ok()).collect();
        let mut relays = self.relays.lock().unwrap_or_else(PoisonError::into_inner);
        relays.retain(|url, h| {
            let keep = wanted.contains(url);
            if !keep {
                h.cancel.cancel();
                self.status
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(url);
            }
            keep
        });
        for url in wanted {
            if relays.contains_key(&url) {
                continue;
            }
            let (tx, rx) = mpsc::channel(64);
            let cancel = self.cancel.child_token();
            relays.insert(
                url.clone(),
                RelayHandle {
                    cmds: tx,
                    cancel: cancel.clone(),
                },
            );
            self.status
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    url.clone(),
                    RelayStatus {
                        url: url.clone(),
                        state: RelayState::Connecting,
                    },
                );
            let link = Link {
                status: self.status.clone(),
                events: self.events_tx.clone(),
                auth: self.auth.clone(),
                tls: self.tls.clone(),
            };
            tokio::spawn(relay_task(url, rx, link, self.pubkeys.subscribe(), cancel));
        }
    }

    /// Sets the transport public keys (hex) to receive requests for; connected relays resubscribe.
    pub fn set_pubkeys(&self, keys: Vec<String>) {
        self.pubkeys.send_replace(keys);
    }

    /// Current relay URLs.
    pub fn urls(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Status of every relay.
    pub fn status(&self) -> Vec<RelayStatus> {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Publishes `event` to every relay and waits (bounded) for their `OK`s. Returns how many
    /// relays accepted it.
    pub async fn publish(&self, event: &Event) -> usize {
        let Ok(json) = serde_json::to_string(&json!(["EVENT", event])) else {
            return 0;
        };
        let id = event.id.to_hex();
        let senders: Vec<mpsc::Sender<Cmd>> = self
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|h| h.cmds.clone())
            .collect();
        let mut waiters = Vec::new();
        for tx in senders {
            let (ack, rx) = oneshot::channel();
            if tx
                .try_send(Cmd::Publish {
                    id: id.clone(),
                    json: json.clone(),
                    ack,
                })
                .is_ok()
            {
                waiters.push(rx);
            }
        }
        let mut ok = 0;
        for w in waiters {
            if matches!(
                tokio::time::timeout(PUBLISH_TIMEOUT, w).await,
                Ok(Ok(Ok(())))
            ) {
                ok += 1;
            }
        }
        ok
    }

    /// Disconnects everything.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

// ---- transport ----------------------------------------------------------------------------

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Ws = tokio_tungstenite::WebSocketStream<Box<dyn Io>>;

fn client_config(roots: rustls::RootCertStore) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    Ok(Arc::new(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

/// A TLS client configuration that trusts exactly `roots` (tests only).
#[cfg(feature = "testing")]
pub(crate) fn trusting_config(
    roots: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut store = rustls::RootCertStore::empty();
    for r in roots {
        store.add(r).map_err(|e| e.to_string())?;
    }
    client_config(store)
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            client_config(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
        })
        .clone()
}

async fn connect(
    url: &str,
    tls_override: Option<&Arc<rustls::ClientConfig>>,
) -> Result<Ws, String> {
    let url = validate_relay(url).map_err(|e| e.to_string())?;
    let parsed = Url::parse(&url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().ok_or("no host")?.to_owned();
    let tls = parsed.scheme() == "wss";
    let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
    let tcp = TcpStream::connect((host.trim_matches(['[', ']']), port))
        .await
        .map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    let stream: Box<dyn Io> = if tls {
        let name =
            rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
        let config = match tls_override {
            Some(c) => c.clone(),
            None => tls_config()?,
        };
        let s = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        Box::new(s)
    } else {
        Box::new(tcp)
    };
    let cfg = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let (ws, _) = tokio_tungstenite::client_async_with_config(url, stream, Some(cfg))
        .await
        .map_err(|e| e.to_string())?;
    Ok(ws)
}

fn set_state(status: &Mutex<BTreeMap<String, RelayStatus>>, url: &str, state: RelayState) {
    let mut g = status.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(s) = g.get_mut(url) {
        s.state = state;
    }
}

/// What a relay task shares with its pool.
struct Link {
    status: Arc<Mutex<BTreeMap<String, RelayStatus>>>,
    events: mpsc::Sender<Incoming>,
    auth: Arc<dyn AuthSigner>,
    tls: Option<Arc<rustls::ClientConfig>>,
}

async fn relay_task(
    url: String,
    mut cmds: mpsc::Receiver<Cmd>,
    link: Link,
    mut pubkeys: watch::Receiver<Vec<String>>,
    cancel: CancellationToken,
) {
    let Link {
        status,
        events,
        auth,
        tls,
    } = link;
    let mut backoff = Duration::from_secs(1);
    loop {
        set_state(&status, &url, RelayState::Connecting);
        match tokio::time::timeout(CONNECT_TIMEOUT, connect(&url, tls.as_ref())).await {
            Ok(Ok(ws)) => {
                set_state(&status, &url, RelayState::Connected);
                let started = Instant::now();
                let why = session(ws, &url, &mut cmds, &events, &auth, &mut pubkeys, &cancel).await;
                if cancel.is_cancelled() {
                    return;
                }
                set_state(&status, &url, RelayState::Failed(why));
                if started.elapsed() > Duration::from_secs(30) {
                    backoff = Duration::from_secs(1);
                }
            }
            Ok(Err(e)) => set_state(&status, &url, RelayState::Failed(e)),
            Err(_) => set_state(
                &status,
                &url,
                RelayState::Failed("connection timed out".into()),
            ),
        }
        // Drop publish commands queued while we were down: their callers have timed out already.
        while cmds.try_recv().is_ok() {}
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn subscription(keys: &[String]) -> Option<String> {
    if keys.is_empty() {
        return None;
    }
    let filter =
        json!({"kinds": [crate::protocol::KIND], "#p": keys, "since": now().saturating_sub(60)});
    serde_json::to_string(&json!(["REQ", SUB_ID, filter])).ok()
}

/// Runs one connection. Returns the reason it ended.
async fn session(
    ws: Ws,
    url: &str,
    cmds: &mut mpsc::Receiver<Cmd>,
    events: &mpsc::Sender<Incoming>,
    auth: &Arc<dyn AuthSigner>,
    pubkeys: &mut watch::Receiver<Vec<String>>,
    cancel: &CancellationToken,
) -> String {
    let (mut sink, mut stream) = ws.split();
    let mut acks: HashMap<String, oneshot::Sender<Result<(), String>>> = HashMap::new();
    let mut last_rx = Instant::now();
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await; // the first tick is immediate

    macro_rules! send {
        ($text:expr) => {
            if sink.send(Message::text($text)).await.is_err() {
                return "write failed".to_owned();
            }
        };
    }
    let subscribe = |keys: &[String]| subscription(keys);
    let first = subscribe(&pubkeys.borrow());
    if let Some(req) = first {
        send!(req);
    }

    loop {
        tokio::select! {
            () = cancel.cancelled() => { let _ = sink.close().await; return "shutdown".into(); }
            _ = ping.tick() => {
                if last_rx.elapsed() > DEAD_AFTER { return "no data from relay (dead connection)".into(); }
                if sink.send(Message::Ping(Vec::new().into())).await.is_err() { return "write failed".into(); }
            }
            changed = pubkeys.changed() => {
                if changed.is_err() { return "shutdown".into(); }
                let keys = pubkeys.borrow_and_update().clone();
                send!(serde_json::to_string(&json!(["CLOSE", SUB_ID])).unwrap_or_default());
                if let Some(req) = subscribe(&keys) { send!(req); }
            }
            cmd = cmds.recv() => match cmd {
                None => return "shutdown".into(),
                Some(Cmd::Publish { id, json, ack }) => {
                    if acks.len() >= 256 { let _ = ack.send(Err("too many unacknowledged events".into())); continue; }
                    acks.insert(id, ack);
                    send!(json);
                }
            },
            msg = stream.next() => {
                let Some(msg) = msg else { return "connection closed by relay".into() };
                let msg = match msg { Ok(m) => m, Err(e) => return format!("connection error: {e}") };
                last_rx = Instant::now();
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => return "closed by relay".into(),
                    _ => continue, // pings are answered by tungstenite; pongs/binary ignored
                };
                let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&text) else { continue };
                match a.first().and_then(Value::as_str) {
                    Some("EVENT") => {
                        if let Some(ev) = a.get(2).and_then(|v| serde_json::from_value::<Event>(v.clone()).ok()) {
                            // Never block the socket on a slow consumer: drop under overload.
                            let _ = events.try_send(Incoming { event: ev, relay: url.to_owned() });
                        }
                    }
                    Some("OK") => {
                        let id = a.get(1).and_then(Value::as_str).unwrap_or_default();
                        let accepted = a.get(2).and_then(Value::as_bool).unwrap_or(false);
                        if let Some(tx) = acks.remove(id) {
                            let reason = a.get(3).and_then(Value::as_str).unwrap_or("rejected").to_owned();
                            let _ = tx.send(if accepted { Ok(()) } else { Err(reason) });
                        }
                    }
                    Some("AUTH") => {
                        if let Some(challenge) = a.get(1).and_then(Value::as_str) {
                            if let Some(ev) = auth.sign_auth(url, challenge) {
                                send!(serde_json::to_string(&json!(["AUTH", ev])).unwrap_or_default());
                                // Resubscribe: a REQ sent before authentication may have been refused.
                                let again = subscribe(&pubkeys.borrow());
                                if let Some(req) = again { send!(req); }
                            }
                        }
                    }
                    Some("CLOSED") => {
                        // e.g. "auth-required: …": the AUTH handler above re-subscribes. Otherwise retry later.
                        let reason = a.get(2).and_then(Value::as_str).unwrap_or_default();
                        if !reason.starts_with("auth-required") { return format!("subscription closed: {reason}"); }
                    }
                    _ => {} // EOSE, NOTICE, unknown: ignored
                }
            }
        }
    }
}
