//! `wss://` over real TLS: the relay client against an in-process relay with a throw-away certificate.
//!
//! Until this file existed no test touched the TLS path at all (every other test uses `ws://` on
//! loopback). What is checked, and what is not:
//!
//! * a complete NIP-46 round trip works through a TLS relay whose certificate the client trusts;
//! * the client **refuses** a certificate from an unknown authority, one issued for another host name,
//!   and an expired one — nothing reaches the relay and no request reaches the handler;
//! * NOT checked: real public relays, the bundled Mozilla root list, certificate revocation, TLS 1.2
//!   vs 1.3 negotiation. The positive test uses the `testing`-only `Service::start_trusting`, which
//!   replaces the roots; the negative tests use the same code path with the production roots.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    unreachable_pub
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use embr_crypto::{Event, Identity, Limits};
use embr_nip46::protocol::{self, KIND, RpcResponse};
use embr_nip46::relay::RelayState;
use embr_nip46::service::{Call, CallFuture, Handler, Service, ServiceConfig};
use embr_nip46::testing::{Options, TestRelay, TlsIdentity};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Counts every call it receives; `ping` → `pong`.
#[derive(Default)]
struct Counting(std::sync::Mutex<Vec<String>>);

impl Handler for Counting {
    fn call(&self, call: Call) -> CallFuture {
        self.0.lock().unwrap().push(call.method.clone());
        Box::pin(async move {
            match call.method.as_str() {
                "ping" => Ok("pong".into()),
                other => Err(format!("unsupported method {other}")),
            }
        })
    }
}

fn client_config(trust: &TlsIdentity) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trust.cert.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A hand-written NIP-46 client that talks to the relay over TLS (the other side of the round trip).
struct TlsClient {
    id: Identity,
    ws: WebSocketStream<TlsStream<TcpStream>>,
}

impl TlsClient {
    async fn connect(relay: &TestRelay, trust: &TlsIdentity) -> TlsClient {
        let url = relay.url();
        assert!(url.starts_with("wss://"), "{url}");
        let tcp = TcpStream::connect(url.trim_start_matches("wss://"))
            .await
            .unwrap();
        let tls = tokio_rustls::TlsConnector::from(client_config(trust))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async(url, tls).await.unwrap();
        let id = Identity::generate();
        let req =
            json!(["REQ", "c", {"kinds": [KIND], "#p": [id.pubkey_hex()], "since": now() - 5}]);
        ws.send(Message::text(req.to_string())).await.unwrap();
        TlsClient { id, ws }
    }

    async fn call(&mut self, signer: &Identity, method: &str) -> Option<RpcResponse> {
        let payload = json!({"id": format!("{method}-{}", now()), "method": method, "params": []})
            .to_string();
        let ev = protocol::seal(
            &self.id,
            &signer.public_key(),
            &payload,
            now(),
            &Limits::default(),
        )
        .unwrap();
        self.ws
            .send(Message::text(json!(["EVENT", ev]).to_string()))
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let msg = tokio::time::timeout_at(deadline, self.ws.next())
                .await
                .ok()??
                .ok()?;
            let Message::Text(t) = msg else { continue };
            let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&t) else {
                continue;
            };
            if a.first().and_then(Value::as_str) == Some("EVENT") {
                let ev: Event = serde_json::from_value(a[2].clone()).unwrap();
                if let Ok(r) = protocol::open_response(&self.id, &ev, &Limits::default()) {
                    return Some(r);
                }
            }
        }
    }
}

/// The service pointed at `relay`; `trust` = the certificate it is told to trust (`None` = production roots).
async fn service_for(
    relay: &TestRelay,
    trust: Option<&TlsIdentity>,
) -> (Arc<Service>, Identity, Arc<Counting>) {
    let handler = Arc::new(Counting::default());
    let cancel = CancellationToken::new();
    let svc = match trust {
        Some(t) => Service::start_trusting(
            handler.clone(),
            ServiceConfig::default(),
            &cancel,
            vec![t.cert.clone()],
        )
        .unwrap(),
        None => Service::start(handler.clone(), ServiceConfig::default(), &cancel),
    };
    let signer = Identity::generate();
    svc.add_signer(Identity::from_secret_bytes(&signer.secret_bytes()).unwrap());
    svc.set_relays(&[relay.url()]);
    (svc, signer, handler)
}

async fn wait_connected(svc: &Service) {
    for _ in 0..500 {
        let st = svc.status();
        if !st.is_empty() && st.iter().all(|s| s.state == RelayState::Connected) {
            tokio::time::sleep(Duration::from_millis(100)).await; // let the REQ land
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("relay never connected: {:?}", svc.status());
}

/// The reason the relay connection failed, once it has.
async fn wait_failed(svc: &Service) -> String {
    for _ in 0..500 {
        for s in svc.status() {
            if let RelayState::Failed(why) = s.state {
                return why;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "the connection neither failed nor succeeded: {:?}",
        svc.status()
    );
}

#[tokio::test]
async fn a_full_nip46_round_trip_works_over_wss() {
    let identity = TlsIdentity::valid_for(&["127.0.0.1"]);
    let relay = TestRelay::start_tls(Options::default(), &identity).await;
    let (svc, signer, handler) = service_for(&relay, Some(&identity)).await;
    wait_connected(&svc).await;

    let mut client = TlsClient::connect(&relay, &identity).await;
    let r = client.call(&signer, "ping").await.expect("no response");
    assert_eq!(r.result.as_deref(), Some("pong"));
    assert_eq!(handler.0.lock().unwrap().as_slice(), ["ping"]);
    // Both directions were encrypted twice over: TLS to the relay, NIP-44 inside. The relay's view of
    // the events is still only ciphertext.
    for ev in relay.events() {
        assert_eq!(ev.kind.as_u16(), KIND);
        assert!(!ev.content.contains("pong") && !ev.content.contains("ping"));
    }
    svc.stop();
}

#[tokio::test]
async fn a_certificate_from_an_unknown_authority_is_refused() {
    // A perfectly valid certificate for the right name, signed by nobody the client trusts: this is what
    // a man in the middle presents. The service runs with the production roots.
    let identity = TlsIdentity::valid_for(&["127.0.0.1"]);
    let relay = TestRelay::start_tls(Options::default(), &identity).await;
    let (svc, _signer, handler) = service_for(&relay, None).await;

    let why = wait_failed(&svc).await;
    assert!(why.contains("UnknownIssuer"), "unexpected failure: {why}");
    // The handshake never completed: no WebSocket, no subscription, no request.
    assert_eq!(relay.total_connections(), 0);
    assert!(relay.events().is_empty());
    assert!(handler.0.lock().unwrap().is_empty());
    svc.stop();
}

#[tokio::test]
async fn a_trusted_certificate_for_another_host_name_is_refused() {
    // The certificate chains to a root the client trusts, but it was issued for a different name: the
    // client must check the name, not just the chain.
    let identity = TlsIdentity::valid_for(&["relay.example.com"]);
    let relay = TestRelay::start_tls(Options::default(), &identity).await;
    let (svc, _signer, handler) = service_for(&relay, Some(&identity)).await;

    let why = wait_failed(&svc).await;
    assert!(
        why.contains("not valid for name"),
        "unexpected failure: {why}"
    );
    assert_eq!(relay.total_connections(), 0);
    assert!(handler.0.lock().unwrap().is_empty());
    svc.stop();
}

#[tokio::test]
async fn an_expired_certificate_is_refused() {
    let identity = TlsIdentity::expired_for(&["127.0.0.1"]);
    let relay = TestRelay::start_tls(Options::default(), &identity).await;
    let (svc, _signer, handler) = service_for(&relay, Some(&identity)).await;

    let why = wait_failed(&svc).await;
    assert!(
        why.contains("certificate expired"),
        "unexpected failure: {why}"
    );
    assert_eq!(relay.total_connections(), 0);
    assert!(handler.0.lock().unwrap().is_empty());
    svc.stop();
}
