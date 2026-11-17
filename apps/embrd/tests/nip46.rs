//! NIP-46 remote signing end to end: real daemon, real control channel, an in-process relay and a
//! hand-written NIP-46 client.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    unreachable_pub
)]

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::*;
use embr_client::control::ControlClient;
use embr_core::AccountMeta;
use embr_crypto::{Identity, Limits};
use embr_ipc::control::{DecisionWire, Nip46Status, PendingKind};
use embr_nip46::protocol::{self, KIND, RpcResponse};
use embr_nip46::testing::{Options, TestRelay};
use embr_nip46::uri::{BunkerUri, NostrConnectUri};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A hand-written NIP-46 client (the thing an app or website would be).
struct N46 {
    id: Identity,
    ws: tokio_tungstenite::WebSocketStream<TcpStream>,
    n: u32,
}

impl N46 {
    async fn connect(relay_url: &str) -> N46 {
        let id = Identity::generate();
        let tcp = TcpStream::connect(relay_url.trim_start_matches("ws://"))
            .await
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async(relay_url.to_owned(), tcp)
            .await
            .unwrap();
        let req =
            json!(["REQ", "c", {"kinds": [KIND], "#p": [id.pubkey_hex()], "since": now() - 5}]);
        ws.send(Message::text(req.to_string())).await.unwrap();
        N46 { id, ws, n: 0 }
    }

    async fn send_raw(&mut self, signer_hex: &str, payload: &str) {
        let signer: embr_crypto::PublicKey = signer_hex.parse().unwrap();
        let ev = protocol::seal(&self.id, &signer, payload, now(), &Limits::default()).unwrap();
        self.ws
            .send(Message::text(json!(["EVENT", ev]).to_string()))
            .await
            .unwrap();
    }

    /// Sends a request and waits (bounded) for the response with the same id.
    async fn call(
        &mut self,
        signer_hex: &str,
        method: &str,
        params: &[&str],
        secs: u64,
    ) -> Option<RpcResponse> {
        self.n += 1;
        let id = format!("{}-{}", method, self.n);
        self.send_raw(
            signer_hex,
            &json!({"id": id, "method": method, "params": params}).to_string(),
        )
        .await;
        self.wait_response(Some(&id), secs).await
    }

    async fn wait_response(&mut self, id: Option<&str>, secs: u64) -> Option<RpcResponse> {
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
            if a.first().and_then(Value::as_str) != Some("EVENT") {
                continue;
            }
            let ev: embr_crypto::Event = serde_json::from_value(a[2].clone()).unwrap();
            if let Ok(r) = protocol::open_response(&self.id, &ev, &Limits::default()) {
                if id.is_none_or(|i| r.id == i) {
                    return Some(r);
                }
            }
        }
    }
}

impl Rig {
    async fn pair_new(&mut self, account: &AccountMeta, name: &str) -> (N46, BunkerUri) {
        let n = N46::connect(&self.relay.url()).await;
        pair(self, n, account, name).await
    }
}

struct Rig {
    env: Env,
    daemon: embrd::DaemonHandle,
    relay: TestRelay,
    ctl: ControlClient,
    accounts: Vec<AccountMeta>,
}

async fn rig(n_accounts: usize) -> Rig {
    let env = Env::new();
    let daemon = boot(&env).await;
    let relay = TestRelay::start(Options::default()).await;
    let (mut ctl, accounts) = vault_with_accounts(&env, n_accounts);
    ctl.call(
        "set_settings",
        json!({"lock_timeout_secs": 900, "notifications": true, "remote_signing_enabled": true, "relays": [relay.url()]}),
    )
    .unwrap();
    let mut r = Rig {
        env,
        daemon,
        relay,
        ctl,
        accounts,
    };
    wait_connected(&mut r.ctl).await;
    r
}

fn status(c: &mut ControlClient) -> Nip46Status {
    serde_json::from_value(c.call("nip46_status", json!({})).unwrap()).unwrap()
}

async fn wait_connected(c: &mut ControlClient) {
    for _ in 0..400 {
        let s = status(c);
        if !s.relays.is_empty() && s.relays.iter().all(|r| r.state == "connected") {
            tokio::time::sleep(Duration::from_millis(150)).await; // let the REQ land
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("relays never connected: {:?}", status(c));
}

fn bunker(c: &mut ControlClient, account: &AccountMeta) -> BunkerUri {
    let v = c
        .call("nip46_bunker", json!({"account": account.id.to_string()}))
        .unwrap();
    BunkerUri::parse(v["uri"].as_str().unwrap()).unwrap()
}

/// Pairs `n46` through a bunker URI: connect with the secret, approve in the control channel.
async fn pair(r: &mut Rig, n46: N46, account: &AccountMeta, name: &str) -> (N46, BunkerUri) {
    let uri = bunker(&mut r.ctl, account);
    let signer = uri.signer.to_string();
    let secret = uri.secret.clone().unwrap();
    let meta = json!({"name": name, "url": "https://app.example"}).to_string();
    let t = tokio::spawn(async move {
        let mut n46 = n46;
        let resp = n46
            .call(
                &signer,
                "connect",
                &[&signer, &secret, "sign_event:1,nip44_encrypt", &meta],
                20,
            )
            .await;
        (n46, resp)
    });
    let v = wait_pending(&mut r.ctl, 1).remove(0);
    assert_eq!(v.kind, PendingKind::Pair);
    assert_eq!(v.client.via, "nip46");
    assert!(
        v.client.peer.is_none(),
        "remote clients have no process hints"
    );
    assert_eq!(v.client.name, name);
    assert_eq!(v.account.as_ref().unwrap().id, account.id);
    assert!(v.text_preview.as_deref().unwrap().contains("app.example"));
    assert_eq!(
        v.requested_permissions,
        ["sign_event:1", "nip44_encrypt"],
        "requested permissions are a wish, shown, never granted"
    );
    r.ctl
        .decide(
            &v,
            DecisionWire::Pair {
                account: account.id,
            },
            None,
        )
        .unwrap();
    let (n46, resp) = t.await.unwrap();
    assert_eq!(resp.unwrap().result.as_deref(), Some("ack"));
    (n46, uri)
}

// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn bunker_flow_pairing_signing_and_encryption() {
    let mut r = rig(1).await;
    let acct = r.accounts[0].clone();
    let (mut n46, uri) = r.pair_new(&acct, "Web Client").await;
    let signer = uri.signer.to_string();
    assert_ne!(
        signer, acct.pubkey_hex,
        "the bunker pubkey is a transport key, never the user's key"
    );

    // get_public_key returns the *user* key.
    let resp = n46.call(&signer, "get_public_key", &[], 10).await.unwrap();
    assert_eq!(resp.result.as_deref(), Some(acct.pubkey_hex.as_str()));

    // A paired client still needs approval for each kind of request.
    let event =
        json!({"kind": 1, "content": "hello over NIP-46", "tags": [["t", "embr"]]}).to_string();
    let (s2, ev2) = (signer.clone(), event.clone());
    let t = tokio::spawn(async move {
        let r = n46.call(&s2, "sign_event", &[&ev2], 20).await;
        (n46, r)
    });
    let v = wait_pending(&mut r.ctl, 1).remove(0);
    assert_eq!(v.kind, PendingKind::Operation);
    assert_eq!(v.client.via, "nip46");
    assert_eq!(v.event.as_ref().unwrap().content, "hello over NIP-46");
    r.ctl
        .decide(&v, DecisionWire::AllowPersistent, exact_kind(1))
        .unwrap();
    let (mut n46, resp) = t.await.unwrap();
    let signed: embr_crypto::Event =
        serde_json::from_str(resp.unwrap().result.as_deref().unwrap()).unwrap();
    signed.verify().unwrap();
    assert_eq!(signed.pubkey.to_hex(), acct.pubkey_hex);

    // The persistent grant applies over NIP-46 too — one policy engine for both transports.
    let resp = n46
        .call(
            &signer,
            "sign_event",
            &[&json!({"kind": 1, "content": "no prompt"}).to_string()],
            10,
        )
        .await
        .unwrap();
    assert!(resp.error.is_none(), "{resp:?}");
    assert!(r.ctl.pending().unwrap().is_empty());

    // Encrypt / decrypt: NIP-44 round trip with another party, decrypt needs its own approval.
    let peer = Identity::generate();
    let (s2, p2) = (signer.clone(), peer.pubkey_hex());
    let t = tokio::spawn(async move {
        let r = n46
            .call(&s2, "nip44_encrypt", &[&p2, "secret words"], 20)
            .await;
        (n46, r)
    });
    let v = wait_pending(&mut r.ctl, 1).remove(0);
    assert_eq!(v.operation.as_deref(), Some("nip44_encrypt"));
    r.ctl.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    let (mut n46, resp) = t.await.unwrap();
    let ct = resp.unwrap().result.unwrap();
    let author: embr_crypto::PublicKey = acct.pubkey_hex.parse().unwrap();
    assert_eq!(
        &*peer
            .nip44_decrypt(&author, &ct, &Limits::default())
            .unwrap(),
        "secret words"
    );

    let back = peer
        .nip44_encrypt(&author, "from the peer", &Limits::default())
        .unwrap();
    let (s2, p2) = (signer.clone(), peer.pubkey_hex());
    let t = tokio::spawn(async move {
        let r = n46.call(&s2, "nip44_decrypt", &[&p2, &back], 20).await;
        (n46, r)
    });
    let v = wait_pending(&mut r.ctl, 1).remove(0);
    assert!(
        v.reveals_plaintext,
        "decrypt returns private data and is flagged"
    );
    r.ctl.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    let (mut n46, resp) = t.await.unwrap();
    assert_eq!(resp.unwrap().result.as_deref(), Some("from the peer"));

    // ping needs no pairing; unsupported methods are refused.
    assert_eq!(
        n46.call(&signer, "ping", &[], 10)
            .await
            .unwrap()
            .result
            .as_deref(),
        Some("pong")
    );
    assert!(
        n46.call(&signer, "sign_psbt", &["x"], 10)
            .await
            .unwrap()
            .error
            .is_some()
    );

    // The relay only ever saw ciphertext.
    for ev in r.relay.events() {
        assert!(!ev.content.contains("secret words") && !ev.content.contains("hello over"));
    }
    // Audit says "nip46" and has no content.
    let log = std::fs::read_to_string(r.env.data.join("audit.jsonl")).unwrap();
    assert!(log.contains("\"via\":\"nip46\"") && !log.contains("hello over NIP-46"));
    drop(r.ctl);
    r.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn secrets_are_single_use_and_unpaired_clients_get_nothing() {
    let mut r = rig(1).await;
    let acct = r.accounts[0].clone();
    let uri = bunker(&mut r.ctl, &acct);
    let signer = uri.signer.to_string();
    let secret = uri.secret.clone().unwrap();
    let mut stranger = N46::connect(&r.relay.url()).await;

    // No secret / wrong secret: refused, and no prompt is ever created.
    let resp = stranger
        .call(&signer, "connect", &[&signer], 10)
        .await
        .unwrap();
    assert!(
        resp.error.as_deref().unwrap().contains("secret"),
        "{resp:?}"
    );
    let resp = stranger
        .call(&signer, "connect", &[&signer, "wrong-secret"], 10)
        .await
        .unwrap();
    assert!(resp.error.is_some());
    // Wrong signer pubkey in params.
    let resp = stranger
        .call(
            &signer,
            "connect",
            &[&Identity::generate().pubkey_hex(), &secret],
            10,
        )
        .await
        .unwrap();
    assert!(resp.error.is_some());
    assert!(r.ctl.pending().unwrap().is_empty());

    // Unpaired clients cannot do anything else, and still produce no prompt.
    for (m, p) in [
        ("get_public_key", vec![]),
        ("sign_event", vec![json!({"kind":1}).to_string()]),
        (
            "nip44_decrypt",
            vec![Identity::generate().pubkey_hex(), "x".into()],
        ),
    ] {
        let p: Vec<&str> = p.iter().map(String::as_str).collect();
        let resp = stranger.call(&signer, m, &p, 10).await.unwrap();
        assert!(
            resp.error.as_deref().unwrap().contains("not connected"),
            "{m}: {resp:?}"
        );
    }
    assert!(r.ctl.pending().unwrap().is_empty());

    // The right secret reaches the prompt; the user rejects; the secret is gone anyway.
    let (s2, sec2) = (signer.clone(), secret.clone());
    let t = tokio::spawn(async move {
        let r = stranger.call(&s2, "connect", &[&s2, &sec2], 20).await;
        (stranger, r)
    });
    let v = wait_pending(&mut r.ctl, 1).remove(0);
    r.ctl.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    let (mut stranger, resp) = t.await.unwrap();
    assert!(resp.unwrap().error.is_some());
    let resp = stranger
        .call(&signer, "connect", &[&signer, &secret], 10)
        .await
        .unwrap();
    assert!(
        resp.error.as_deref().unwrap().contains("secret"),
        "a used secret must not work again"
    );
    assert_eq!(code_count(&r), 0);
    r.daemon.shutdown().await;
}

fn code_count(r: &Rig) -> usize {
    r.relay
        .events()
        .iter()
        .filter(|e| e.kind.as_u16() != KIND)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_client_cannot_use_another_accounts_transport_key() {
    let mut r = rig(2).await;
    let (a, b) = (r.accounts[0].clone(), r.accounts[1].clone());
    let (mut n46, uri_a) = r.pair_new(&a, "client of A").await;
    let uri_b = bunker(&mut r.ctl, &b); // creates B's transport key and starts listening on it
    wait_connected(&mut r.ctl).await;
    assert_ne!(uri_a.signer, uri_b.signer);

    let resp = n46
        .call(&uri_b.signer.to_string(), "get_public_key", &[], 10)
        .await
        .unwrap();
    assert!(
        resp.error.is_some(),
        "paired to A, addressing B's transport key: {resp:?}"
    );
    assert!(!resp.result.is_some_and(|x| x == b.pubkey_hex));
    // Using B's secret from a client key that is paired only to A does not bind it to B either
    // unless the user approves, and the prompt names B.
    let (sb, secb) = (uri_b.signer.to_string(), uri_b.secret.clone().unwrap());
    let t = tokio::spawn(async move {
        let r = n46.call(&sb, "connect", &[&sb, &secb], 20).await;
        (n46, r)
    });
    let v = wait_pending(&mut r.ctl, 1).remove(0);
    assert_eq!(v.account.as_ref().unwrap().id, b.id);
    // Approving with the wrong account is refused (the connection is bound to B's transport key).
    let e = r
        .ctl
        .decide(&v, DecisionWire::Pair { account: a.id }, None)
        .unwrap_err();
    assert!(
        matches!(&e, embr_client::ClientError::Rpc(x) if x.code == embr_ipc::ErrorCode::InvalidParams as u16),
        "{e:?}"
    );
    r.ctl.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    drop(t.await.unwrap());
    r.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn nostrconnect_import_contacts_client_relays_only_after_approval() {
    let mut r = rig(1).await;
    let acct = r.accounts[0].clone();
    let client_relay = TestRelay::start(Options::default()).await; // only the *client* knows this relay
    let mut n46 = N46::connect(&client_relay.url()).await;
    let secret = "s3cr3t-from-client";
    let uri = format!(
        "nostrconnect://{}?relay={}&secret={secret}&perms=sign_event%3A1&name=Browser+App&url=https%3A%2F%2Fapp.example",
        n46.id.pubkey_hex(),
        client_relay.url().replace(':', "%3A").replace('/', "%2F")
    );
    NostrConnectUri::parse(&uri).unwrap();

    let v = r
        .ctl
        .call(
            "nip46_connect",
            json!({"uri": uri, "account": acct.id.to_string()}),
        )
        .unwrap();
    assert!(v["pending_id"].is_number());
    let view = wait_pending(&mut r.ctl, 1).remove(0);
    assert_eq!(view.kind, PendingKind::Pair);
    assert_eq!(view.client.pubkey.to_string(), n46.id.pubkey_hex());
    assert_eq!(view.client.name, "Browser App");
    assert!(
        view.text_preview
            .as_ref()
            .unwrap()
            .contains(&client_relay.url()),
        "the prompt shows which relays will be contacted"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        client_relay.total_connections(),
        1,
        "only the test client itself: the daemon must not have connected yet"
    );

    r.ctl
        .decide(&view, DecisionWire::Pair { account: acct.id }, None)
        .unwrap();
    // After approval the daemon connects to the client's relay and answers with the secret (NIP-46).
    let resp = n46.wait_response(None, 20).await.expect("connect response");
    assert_eq!(resp.result.as_deref(), Some(secret));
    assert!(client_relay.total_connections() >= 2);

    // And now serves the client on that relay.
    let signer = status(&mut r.ctl).signers[0].transport_pubkey.to_string();
    let resp = n46.call(&signer, "get_public_key", &[], 15).await.unwrap();
    assert_eq!(resp.result.as_deref(), Some(acct.pubkey_hex.as_str()));

    // Rejected imports never cause a connection.
    let relay_b = TestRelay::start(Options::default()).await;
    let n2 = N46::connect(&relay_b.url()).await;
    let uri2 = format!(
        "nostrconnect://{}?relay={}&secret=x",
        n2.id.pubkey_hex(),
        relay_b.url().replace(':', "%3A").replace('/', "%2F")
    );
    r.ctl
        .call(
            "nip46_connect",
            json!({"uri": uri2, "account": acct.id.to_string()}),
        )
        .unwrap();
    let v2 = wait_pending(&mut r.ctl, 1).remove(0);
    r.ctl.decide(&v2, DecisionWire::RejectOnce, None).unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        relay_b.total_connections(),
        1,
        "a rejected nostrconnect URI must never make the daemon connect to its relay"
    );

    // Hostile URIs are refused outright.
    for bad in [
        "nostrconnect://zz?relay=wss://r.example&secret=x".to_string(),
        format!(
            "nostrconnect://{}?relay=ws://evil.example&secret=x",
            n2.id.pubkey_hex()
        ),
        "http://x".into(),
    ] {
        assert!(
            r.ctl
                .call(
                    "nip46_connect",
                    json!({"uri": bad, "account": acct.id.to_string()})
                )
                .is_err()
        );
    }
    r.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn remote_signing_is_off_by_default_silent_and_follows_the_vault_lock() {
    let env = Env::new();
    let daemon = boot(&env).await;
    let relay = TestRelay::start(Options::default()).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        relay.total_connections(),
        0,
        "defaults: no network activity"
    );
    let s = status(&mut c);
    assert!(!s.enabled && !s.running && s.relays.is_empty());
    assert!(
        c.call("nip46_bunker", json!({"account": accts[0].id.to_string()}))
            .is_err(),
        "no bunker URI while remote signing is off"
    );

    // Enabled but no relays: still silent. (Relay URLs are validated.)
    let on = |relays: Value| json!({"lock_timeout_secs": 900, "notifications": true, "remote_signing_enabled": true, "relays": relays});
    c.call("set_settings", on(json!([]))).unwrap();
    assert!(
        c.call("set_settings", on(json!(["ws://evil.example"])))
            .is_err()
    );
    assert!(
        c.call("set_settings", on(json!(["https://x.example"])))
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(relay.total_connections(), 0);

    c.call("set_settings", on(json!([relay.url()]))).unwrap();
    wait_connected(&mut c).await;
    assert_eq!(relay.connections(), 1);

    // Lock: disconnects and forgets; the setting survives (it lives in the vault) and the service
    // comes back at unlock.
    c.call("lock", json!({})).unwrap();
    for _ in 0..100 {
        if relay.connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        relay.connections(),
        0,
        "locking must disconnect from every relay"
    );
    let mut c2 = ctl(&env);
    c2.unlock(PW).unwrap();
    wait_connected(&mut c2).await;
    assert_eq!(relay.connections(), 1);

    // Turning it off disconnects again.
    c2.call("set_settings", json!({"lock_timeout_secs": 900, "notifications": true, "remote_signing_enabled": false, "relays": [relay.url()]})).unwrap();
    for _ in 0..100 {
        if relay.connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(relay.connections(), 0);
    assert!(!status(&mut c2).running);
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn revocation_blocking_and_lock_over_nip46() {
    let mut r = rig(1).await;
    let acct = r.accounts[0].clone();
    let (mut n46, uri) = r.pair_new(&acct, "app").await;
    let signer = uri.signer.to_string();
    let key = n46.id.pubkey_hex();

    // A pending request is cancelled with a response (not left hanging) when the vault locks.
    let (s2, ev) = (
        signer.clone(),
        json!({"kind": 1, "content": "x"}).to_string(),
    );
    let t = tokio::spawn(async move {
        let r = n46.call(&s2, "sign_event", &[&ev], 20).await;
        (n46, r)
    });
    wait_pending(&mut r.ctl, 1);
    r.ctl.call("lock", json!({})).unwrap();
    let (mut n46, resp) = t.await.unwrap();
    assert!(
        resp.unwrap().error.is_some(),
        "pending NIP-46 requests are answered when the vault locks"
    );
    let resp = n46.call(&signer, "get_public_key", &[], 10).await;
    assert!(
        resp.is_none() || resp.unwrap().error.is_some(),
        "a locked signer must not serve anything"
    );

    // Unlock, revoke: the client is forgotten and must pair again with a fresh secret.
    let mut c2 = ctl(&r.env);
    c2.unlock(PW).unwrap();
    wait_connected(&mut c2).await;
    let resp = n46.call(&signer, "get_public_key", &[], 10).await.unwrap();
    assert_eq!(
        resp.result.as_deref(),
        Some(acct.pubkey_hex.as_str()),
        "pairing survives a lock/unlock cycle (stored encrypted)"
    );
    c2.call("revoke_client", json!({"key": key})).unwrap();
    let resp = n46.call(&signer, "get_public_key", &[], 10).await.unwrap();
    assert!(resp.error.as_deref().unwrap().contains("not connected"));
    r.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn replay_flood_and_relay_outage() {
    let mut r = rig(1).await;
    let acct = r.accounts[0].clone();
    let (mut n46, uri) = r.pair_new(&acct, "app").await;
    let signer = uri.signer.to_string();

    // Replay: the same signed event delivered again (by the relay or an attacker) runs once.
    let payload = json!({"id": "dup", "method": "get_public_key", "params": []}).to_string();
    let signer_pk: embr_crypto::PublicKey = signer.parse().unwrap();
    let ev = protocol::seal(&n46.id, &signer_pk, &payload, now(), &Limits::default()).unwrap();
    n46.ws
        .send(Message::text(json!(["EVENT", ev]).to_string()))
        .await
        .unwrap();
    assert!(n46.wait_response(Some("dup"), 10).await.is_some());
    r.relay.inject(&ev);
    r.relay.inject(&ev);
    assert!(
        n46.wait_response(Some("dup"), 2).await.is_none(),
        "a replayed request must not be answered again"
    );

    // Flood: far more than the per-client budget; the daemon stays healthy and answers other clients.
    for i in 0..150 {
        n46.send_raw(
            &signer,
            &json!({"id": format!("f{i}"), "method": "ping", "params": []}).to_string(),
        )
        .await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        r.ctl.status().unwrap().vault,
        embr_ipc::control::VaultState::Unlocked
    );
    let mut other = N46::connect(&r.relay.url()).await;
    assert_eq!(
        other
            .call(&signer, "ping", &[], 10)
            .await
            .unwrap()
            .result
            .as_deref(),
        Some("pong"),
        "an unrelated client is not starved"
    );

    // Relay outage: everyone dropped; the daemon reconnects by itself and serves again.
    r.relay.drop_connections();
    tokio::time::sleep(Duration::from_millis(300)).await;
    wait_connected(&mut r.ctl).await;
    let mut again = N46::connect(&r.relay.url()).await;
    assert_eq!(
        again
            .call(&signer, "ping", &[], 15)
            .await
            .unwrap()
            .result
            .as_deref(),
        Some("pong"),
        "service recovered after the outage"
    );
    r.daemon.shutdown().await;
}
