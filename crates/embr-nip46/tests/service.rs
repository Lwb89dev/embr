//! The NIP-46 service against an in-process relay and a hand-written client.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    unreachable_pub
)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use embr_crypto::{Event, EventTemplate, Identity, Limits};
use embr_nip46::protocol::{self, KIND, RpcResponse};
use embr_nip46::relay::RelayState;
use embr_nip46::service::{Call, CallFuture, Handler, Service, ServiceConfig};
use embr_nip46::testing::{Options, TestRelay};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `ping` → `pong`; `echo` → first param; anything else → error.
struct Echo(std::sync::Mutex<Vec<String>>);

impl Handler for Echo {
    fn call(&self, call: Call) -> CallFuture {
        self.0.lock().unwrap().push(call.method.clone());
        Box::pin(async move {
            match call.method.as_str() {
                "ping" => Ok("pong".into()),
                "echo" => Ok(call.params.first().cloned().unwrap_or_default()),
                other => Err(format!("unsupported method {other}")),
            }
        })
    }
}

struct Client {
    id: Identity,
    ws: tokio_tungstenite::WebSocketStream<TcpStream>,
}

impl Client {
    async fn connect(relay: &TestRelay) -> Client {
        let id = Identity::generate();
        let url = relay.url();
        let tcp = TcpStream::connect(url.trim_start_matches("ws://"))
            .await
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async(url, tcp).await.unwrap();
        let req =
            json!(["REQ", "c", {"kinds": [KIND], "#p": [id.pubkey_hex()], "since": now() - 5}]);
        ws.send(Message::text(req.to_string())).await.unwrap();
        Client { id, ws }
    }

    fn request_event(&self, signer: &Identity, payload: &str, created_at: u64) -> Event {
        protocol::seal(
            &self.id,
            &signer.public_key(),
            payload,
            created_at,
            &Limits::default(),
        )
        .unwrap()
    }

    async fn publish(&mut self, ev: &Event) {
        self.ws
            .send(Message::text(json!(["EVENT", ev]).to_string()))
            .await
            .unwrap();
    }

    async fn request(&mut self, signer: &Identity, method: &str, params: &[&str]) -> Event {
        let payload =
            json!({"id": format!("{method}-{}", now()), "method": method, "params": params})
                .to_string();
        let ev = self.request_event(signer, &payload, now());
        self.publish(&ev).await;
        ev
    }

    /// Next response for this client within `secs` seconds.
    async fn response(&mut self, secs: u64) -> Option<RpcResponse> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
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

async fn setup(
    opts: Options,
    cfg: ServiceConfig,
) -> (TestRelay, Arc<Service>, Identity, Arc<Echo>) {
    let relay = TestRelay::start(opts).await;
    let handler = Arc::new(Echo(Default::default()));
    let svc = Service::start(handler.clone(), cfg, &CancellationToken::new());
    let signer = Identity::generate();
    svc.add_signer(Identity::from_secret_bytes(&signer.secret_bytes()).unwrap());
    svc.set_relays(&[relay.url()]);
    wait_connected(&svc).await;
    (relay, svc, signer, handler)
}

async fn wait_connected(svc: &Service) {
    for _ in 0..300 {
        if svc
            .status()
            .iter()
            .all(|s| s.state == RelayState::Connected)
            && !svc.status().is_empty()
        {
            tokio::time::sleep(Duration::from_millis(100)).await; // let the REQ land
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("relay never connected: {:?}", svc.status());
}

#[tokio::test]
async fn round_trip_through_a_relay() {
    let (relay, svc, signer, h) = setup(Options::default(), ServiceConfig::default()).await;
    let mut c = Client::connect(&relay).await;
    c.request(&signer, "ping", &[]).await;
    assert_eq!(c.response(5).await.unwrap().result.as_deref(), Some("pong"));
    c.request(&signer, "echo", &["héllo 🔥"]).await;
    assert_eq!(
        c.response(5).await.unwrap().result.as_deref(),
        Some("héllo 🔥")
    );
    c.request(&signer, "nope", &[]).await;
    assert_eq!(
        c.response(5).await.unwrap().error.as_deref(),
        Some("unsupported method nope")
    );
    assert_eq!(h.0.lock().unwrap().as_slice(), ["ping", "echo", "nope"]);
    // Responses are signed by the transport key, never anything else; and the relay only ever saw ciphertext.
    for ev in relay.events() {
        assert_eq!(ev.kind.as_u16(), KIND);
        assert!(!ev.content.contains("pong") && !ev.content.contains("héllo"));
    }
    svc.stop();
}

#[tokio::test]
async fn hostile_events_are_dropped_before_reaching_the_handler() {
    let cfg = ServiceConfig {
        rate_burst: 100,
        rate_per_sec: 100,
        freshness_secs: 5,
        ..ServiceConfig::default()
    };
    let (relay, svc, signer, h) = setup(Options::default(), cfg).await;
    let mut c = Client::connect(&relay).await;
    let payload = json!({"id": "x", "method": "ping", "params": []}).to_string();

    // Replay: the very same event published twice is handled once.
    let ev = c.request_event(&signer, &payload, now());
    c.publish(&ev).await;
    assert_eq!(c.response(5).await.unwrap().result.as_deref(), Some("pong"));
    c.publish(&ev).await; // the relay stores it again and forwards it again
    relay.inject(&ev);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(svc.stats.dropped_replay.load(Ordering::Relaxed) >= 1);
    assert_eq!(
        h.0.lock().unwrap().len(),
        1,
        "a replayed event must not be executed twice"
    );

    // Old and future events. (The relay's own `since` filter would drop ancient ones; the service must
    // not rely on that, because a hostile relay can ignore filters: freshness is 5 s in this test.)
    for t in [now() - 30, now() + 30] {
        let ev = c.request_event(&signer, &payload.replace("\"x\"", &format!("\"t{t}\"")), t);
        c.publish(&ev).await;
    }
    // Addressed to a different signer; wrong kind; not encrypted; forged.
    let other = Identity::generate();
    c.publish(&c.request_event(&other, &payload, now())).await;
    let tpl = EventTemplate {
        kind: 1,
        content: String::new(),
        tags: vec![vec!["p".into(), signer.pubkey_hex()]],
        created_at: Some(now()),
        pubkey: None,
        id: None,
    };
    c.publish(&c.id.sign_event(&tpl, &Limits::default()).unwrap())
        .await;
    let tpl = EventTemplate {
        kind: KIND,
        content: "plaintext".into(),
        tags: vec![vec!["p".into(), signer.pubkey_hex()]],
        created_at: Some(now()),
        pubkey: None,
        id: None,
    };
    c.publish(&c.id.sign_event(&tpl, &Limits::default()).unwrap())
        .await;
    let mut forged = serde_json::to_value(c.request_event(
        &signer,
        &payload.replace("\"x\"", "\"forged\""),
        now(),
    ))
    .unwrap();
    forged["content"] = "AAAA".into();
    c.ws.send(Message::text(json!(["EVENT", forged]).to_string()))
        .await
        .unwrap(); // the relay rejects it; inject directly instead:
    relay.inject(&serde_json::from_value(forged).unwrap());
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert_eq!(
        h.0.lock().unwrap().len(),
        1,
        "nothing hostile may reach the handler"
    );
    let s = &svc.stats;
    assert!(
        s.dropped_stale.load(Ordering::Relaxed) >= 2,
        "stale + future"
    );
    assert!(
        s.dropped_undecodable.load(Ordering::Relaxed) >= 1,
        "unencrypted content"
    );
    // (The relay itself filters other signers and other kinds; the forged-signature event is the one a
    // hostile relay could still deliver, and it must be dropped by the service.)
    assert!(
        s.dropped_invalid.load(Ordering::Relaxed) >= 1,
        "forged signature"
    );
    svc.stop();
}

#[tokio::test]
async fn per_client_rate_limit_applies_before_decryption() {
    let cfg = ServiceConfig {
        rate_burst: 3,
        rate_per_sec: 1,
        ..ServiceConfig::default()
    };
    let (relay, svc, signer, h) = setup(Options::default(), cfg).await;
    let mut c = Client::connect(&relay).await;
    for i in 0..20 {
        let payload = json!({"id": format!("r{i}"), "method": "ping", "params": []}).to_string();
        c.publish(&c.request_event(&signer, &payload, now())).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    let handled = h.0.lock().unwrap().len();
    assert!(
        (3..=5).contains(&handled),
        "burst of 3 (+refill) only, got {handled}"
    );
    assert!(svc.stats.dropped_rate.load(Ordering::Relaxed) >= 15);
    // A different client is not affected by the first one's flood.
    let mut d = Client::connect(&relay).await;
    d.request(&signer, "ping", &[]).await;
    assert_eq!(d.response(5).await.unwrap().result.as_deref(), Some("pong"));
    svc.stop();
}

#[tokio::test]
async fn nip42_auth_relays_are_supported_with_the_transport_key() {
    let (relay, svc, signer, _h) =
        setup(Options { require_auth: true }, ServiceConfig::default()).await;
    // Give the AUTH round trip time to complete.
    for _ in 0..100 {
        if relay.auth_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        relay.auth_count() >= 1,
        "the service must answer the relay's AUTH challenge"
    );
    // The client must authenticate too to publish/subscribe on this relay; do it with its own key.
    let id = Identity::generate();
    let url = relay.url();
    let tcp = TcpStream::connect(url.trim_start_matches("ws://"))
        .await
        .unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(url.clone(), tcp)
        .await
        .unwrap();
    let challenge = loop {
        let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
            continue;
        };
        let a: Vec<Value> = serde_json::from_str(&t).unwrap();
        if a[0] == "AUTH" {
            break a[1].as_str().unwrap().to_owned();
        }
    };
    let tpl = EventTemplate {
        kind: 22242,
        content: String::new(),
        tags: vec![
            vec!["relay".into(), url],
            vec!["challenge".into(), challenge],
        ],
        created_at: Some(now()),
        pubkey: None,
        id: None,
    };
    ws.send(Message::text(
        json!(["AUTH", id.sign_event(&tpl, &Limits::default()).unwrap()]).to_string(),
    ))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    ws.send(Message::text(
        json!(["REQ", "c", {"kinds": [KIND], "#p": [id.pubkey_hex()], "since": now() - 5}])
            .to_string(),
    ))
    .await
    .unwrap();
    let mut c = Client { id, ws };
    c.request(&signer, "ping", &[]).await;
    assert_eq!(c.response(5).await.unwrap().result.as_deref(), Some("pong"));
    svc.stop();
}

#[tokio::test]
async fn reconnects_after_the_relay_drops_everyone() {
    let (relay, svc, signer, _h) = setup(Options::default(), ServiceConfig::default()).await;
    assert_eq!(relay.total_connections(), 1);
    relay.drop_connections();
    // The service notices, backs off (1 s) and reconnects + resubscribes by itself.
    let mut states = Vec::new();
    for _ in 0..300 {
        states.push(svc.status()[0].state.clone());
        if relay.total_connections() >= 2 && svc.status()[0].state == RelayState::Connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        relay.total_connections() >= 2,
        "no reconnection: {states:?}"
    );
    assert!(
        states
            .iter()
            .any(|s| matches!(s, RelayState::Failed(_) | RelayState::Connecting)),
        "the outage must be visible in the status"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut c = Client::connect(&relay).await;
    c.request(&signer, "ping", &[]).await;
    assert_eq!(
        c.response(5).await.unwrap().result.as_deref(),
        Some("pong"),
        "service works again after recovery"
    );
    svc.stop();
}

#[tokio::test]
async fn nothing_connects_until_relays_are_set_and_removing_them_disconnects() {
    let relay = TestRelay::start(Options::default()).await;
    let handler = Arc::new(Echo(Default::default()));
    let svc = Service::start(handler, ServiceConfig::default(), &CancellationToken::new());
    svc.add_signer(Identity::generate());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        relay.total_connections(),
        0,
        "a service without relays is silent"
    );
    assert!(svc.status().is_empty());

    svc.set_relays(&[relay.url()]);
    wait_connected(&svc).await;
    assert_eq!(relay.connections(), 1);
    svc.set_relays(&[]);
    for _ in 0..100 {
        if relay.connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(relay.connections(), 0, "removing the relays disconnects");

    // Invalid relay URLs are ignored, never contacted.
    svc.set_relays(&[
        "ws://evil.example".into(),
        "https://x".into(),
        "wss://user:pw@r.example".into(),
    ]);
    assert!(svc.status().is_empty());
    svc.stop();
}

#[tokio::test]
async fn stopping_the_service_disconnects() {
    let (relay, svc, _signer, _h) = setup(Options::default(), ServiceConfig::default()).await;
    assert_eq!(relay.connections(), 1);
    svc.stop();
    for _ in 0..100 {
        if relay.connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(relay.connections(), 0);
}
