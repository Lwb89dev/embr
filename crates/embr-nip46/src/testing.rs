//! A minimal in-process Nostr relay for tests and the interoperability harness.
//!
//! Supports NIP-01 `EVENT` / `REQ` / `CLOSE` with filters `kinds`, `#p`, `authors`, `ids`,
//! `since`, `until`; optional NIP-42 `AUTH`; and test hooks to inspect stored events, count
//! connections and forcibly drop them; [`TestRelay::start_tls`] serves `wss://` with a throw-away
//! certificate ([`TlsIdentity`]). **Not** a production relay (no limits, no persistence).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    unreachable_pub
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use embr_crypto::Event;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

/// Relay options.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Require NIP-42 authentication before accepting `REQ`/`EVENT`.
    pub require_auth: bool,
}

type Sub = (String, Vec<Value>);

struct Inner {
    events: Mutex<Vec<Event>>,
    conns: Mutex<HashMap<u64, ConnEntry>>,
    next_conn: AtomicU64,
    open: AtomicUsize,
    total: AtomicU64,
    auths: AtomicU64,
    opts: Options,
}

struct ConnEntry {
    tx: mpsc::UnboundedSender<String>,
    subs: Vec<Sub>,
    cancel: CancellationToken,
}

/// A running test relay.
pub struct TestRelay {
    addr: SocketAddr,
    inner: Arc<Inner>,
    stop: CancellationToken,
    tls: bool,
}

/// A freshly generated, self-signed certificate and its key, for a TLS test relay.
pub struct TlsIdentity {
    /// The certificate (DER). A client that should trust this relay is given exactly this as a root.
    pub cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl TlsIdentity {
    /// Valid now, for the given DNS names / IP addresses (e.g. `"127.0.0.1"`).
    pub fn valid_for(names: &[&str]) -> TlsIdentity {
        Self::build(names, false)
    }

    /// For the given names, but expired years ago.
    pub fn expired_for(names: &[&str]) -> TlsIdentity {
        Self::build(names, true)
    }

    fn build(names: &[&str], expired: bool) -> TlsIdentity {
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let cert = params.self_signed(&key).unwrap();
        TlsIdentity {
            cert: cert.der().clone(),
            key: key.serialize_der(),
        }
    }

    fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![self.cert.clone()],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.key.clone())),
            )
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    }
}

fn matches(f: &Value, ev: &Event) -> bool {
    let list = |k: &str| f.get(k).and_then(Value::as_array);
    if let Some(kinds) = list("kinds") {
        if !kinds
            .iter()
            .any(|k| k.as_u64() == Some(u64::from(ev.kind.as_u16())))
        {
            return false;
        }
    }
    if let Some(ps) = list("#p") {
        let tagged: Vec<String> = ev
            .tags
            .iter()
            .filter_map(|t| match t.as_slice() {
                [k, v, ..] if k == "p" => Some(v.clone()),
                _ => None,
            })
            .collect();
        if !ps
            .iter()
            .filter_map(Value::as_str)
            .any(|p| tagged.iter().any(|t| t == p))
        {
            return false;
        }
    }
    if let Some(a) = list("authors") {
        if !a
            .iter()
            .filter_map(Value::as_str)
            .any(|x| x == ev.pubkey.to_hex())
        {
            return false;
        }
    }
    if let Some(i) = list("ids") {
        if !i
            .iter()
            .filter_map(Value::as_str)
            .any(|x| x == ev.id.to_hex())
        {
            return false;
        }
    }
    if f.get("since")
        .and_then(Value::as_u64)
        .is_some_and(|s| ev.created_at.as_secs() < s)
    {
        return false;
    }
    if f.get("until")
        .and_then(Value::as_u64)
        .is_some_and(|u| ev.created_at.as_secs() > u)
    {
        return false;
    }
    true
}

impl Inner {
    fn store_and_forward(&self, ev: &Event) {
        self.events.lock().unwrap().push(ev.clone());
        for c in self.conns.lock().unwrap().values() {
            for (sub, filters) in &c.subs {
                if filters.iter().any(|f| matches(f, ev)) {
                    let _ = c.tx.send(json!(["EVENT", sub, ev]).to_string());
                }
            }
        }
    }
}

impl TestRelay {
    /// Starts a relay on a free loopback port.
    pub async fn start(opts: Options) -> TestRelay {
        Self::start_inner(opts, None).await
    }

    /// Starts a relay that speaks TLS (`wss://127.0.0.1:<port>`) with `identity`'s certificate.
    pub async fn start_tls(opts: Options, identity: &TlsIdentity) -> TestRelay {
        Self::start_inner(opts, Some(identity.acceptor())).await
    }

    async fn start_inner(opts: Options, tls: Option<tokio_rustls::TlsAcceptor>) -> TestRelay {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let inner = Arc::new(Inner {
            events: Mutex::new(Vec::new()),
            conns: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            open: AtomicUsize::new(0),
            total: AtomicU64::new(0),
            auths: AtomicU64::new(0),
            opts,
        });
        let stop = CancellationToken::new();
        let (i2, s2) = (inner.clone(), stop.clone());
        let is_tls = tls.is_some();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = s2.cancelled() => return,
                    r = listener.accept() => {
                        let Ok((sock, _)) = r else { continue };
                        let (inner, cancel, tls) = (i2.clone(), s2.child_token(), tls.clone());
                        // The handshake runs in the connection's own task, so a client that fails it
                        // (that is what the negative tests do) cannot stall the accept loop.
                        tokio::spawn(async move {
                            match tls {
                                Some(acceptor) => {
                                    if let Ok(stream) = acceptor.accept(sock).await {
                                        handle(inner, stream, cancel).await;
                                    }
                                }
                                None => handle(inner, sock, cancel).await,
                            }
                        });
                    }
                }
            }
        });
        TestRelay {
            addr,
            inner,
            stop,
            tls: is_tls,
        }
    }

    /// `ws://127.0.0.1:<port>`, or `wss://…` for a TLS relay.
    pub fn url(&self) -> String {
        format!("{}://{}", if self.tls { "wss" } else { "ws" }, self.addr)
    }

    /// Currently open connections.
    pub fn connections(&self) -> usize {
        self.inner.open.load(Ordering::Acquire)
    }

    /// Connections accepted since the start.
    pub fn total_connections(&self) -> u64 {
        self.inner.total.load(Ordering::Acquire)
    }

    /// Valid NIP-42 AUTH events received.
    pub fn auth_count(&self) -> u64 {
        self.inner.auths.load(Ordering::Acquire)
    }

    /// All stored events.
    pub fn events(&self) -> Vec<Event> {
        self.inner.events.lock().unwrap().clone()
    }

    /// Injects an event as if a client had published it.
    pub fn inject(&self, ev: &Event) {
        self.inner.store_and_forward(ev);
    }

    /// Closes every open connection (the listener keeps accepting): simulates a relay outage.
    pub fn drop_connections(&self) {
        for c in self.inner.conns.lock().unwrap().values() {
            c.cancel.cancel();
        }
    }

    /// Stops the relay.
    pub fn stop(&self) {
        self.stop.cancel();
        self.drop_connections();
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    inner: Arc<Inner>,
    sock: S,
    cancel: CancellationToken,
) {
    let Ok(ws) = tokio_tungstenite::accept_async(sock).await else {
        return;
    };
    let id = inner.next_conn.fetch_add(1, Ordering::Relaxed);
    inner.open.fetch_add(1, Ordering::AcqRel);
    inner.total.fetch_add(1, Ordering::AcqRel);
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    inner.conns.lock().unwrap().insert(
        id,
        ConnEntry {
            tx: tx.clone(),
            subs: Vec::new(),
            cancel: cancel.clone(),
        },
    );
    let (mut sink, mut stream) = ws.split();

    let challenge = format!("{:032x}", id.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut authed = !inner.opts.require_auth;
    if inner.opts.require_auth {
        let _ = tx.send(json!(["AUTH", challenge]).to_string());
    }

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            out = rx.recv() => match out {
                Some(text) => { if sink.send(Message::text(text)).await.is_err() { break; } }
                None => break,
            },
            msg = stream.next() => {
                let Some(Ok(msg)) = msg else { break };
                let Message::Text(text) = msg else { if matches!(msg, Message::Close(_)) { break } else { continue } };
                let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&text) else { continue };
                match a.first().and_then(Value::as_str) {
                    Some("AUTH") => {
                        let ev = a.get(1).and_then(|v| serde_json::from_value::<Event>(v.clone()).ok());
                        let ok = ev.is_some_and(|e| {
                            e.kind.as_u16() == 22242
                                && e.verify().is_ok()
                                && e.tags.iter().any(|t| matches!(t.as_slice(), [k, v, ..] if k == "challenge" && *v == challenge))
                                && e.tags.iter().any(|t| matches!(t.as_slice(), [k, ..] if k == "relay"))
                        });
                        if ok { authed = true; inner.auths.fetch_add(1, Ordering::AcqRel); }
                    }
                    Some("EVENT") => {
                        let Some(ev) = a.get(1).and_then(|v| serde_json::from_value::<Event>(v.clone()).ok()) else { continue };
                        let eid = ev.id.to_hex();
                        if !authed { let _ = tx.send(json!(["OK", eid, false, "auth-required: authenticate first"]).to_string()); continue; }
                        if ev.verify().is_err() { let _ = tx.send(json!(["OK", eid, false, "invalid: bad signature"]).to_string()); continue; }
                        inner.store_and_forward(&ev);
                        let _ = tx.send(json!(["OK", eid, true, ""]).to_string());
                    }
                    Some("REQ") => {
                        let Some(sub) = a.get(1).and_then(Value::as_str).map(str::to_owned) else { continue };
                        if !authed { let _ = tx.send(json!(["CLOSED", sub, "auth-required: authenticate first"]).to_string()); continue; }
                        let filters: Vec<Value> = a.iter().skip(2).cloned().collect();
                        for ev in inner.events.lock().unwrap().iter() {
                            if filters.iter().any(|f| matches(f, ev)) { let _ = tx.send(json!(["EVENT", sub, ev]).to_string()); }
                        }
                        let _ = tx.send(json!(["EOSE", sub]).to_string());
                        if let Some(c) = inner.conns.lock().unwrap().get_mut(&id) {
                            c.subs.retain(|(s, _)| *s != sub);
                            c.subs.push((sub, filters));
                        }
                    }
                    Some("CLOSE") => {
                        if let (Some(sub), Some(c)) = (a.get(1).and_then(Value::as_str), inner.conns.lock().unwrap().get_mut(&id)) {
                            c.subs.retain(|(s, _)| s != sub);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    inner.conns.lock().unwrap().remove(&id);
    inner.open.fetch_sub(1, Ordering::AcqRel);
}
