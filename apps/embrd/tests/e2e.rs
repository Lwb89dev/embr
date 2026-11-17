//! End-to-end tests: a real daemon, real Unix sockets, the real SDK and control clients.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::time::Duration;

use common::*;
use embr_client::ClientError;
use embr_crypto::{Identity, Limits};
use embr_ipc::ErrorCode;
use embr_ipc::control::{ControlEvent, DecisionWire, PendingKind, ScopeWire, VaultState};
use embr_policy::KindScope;
use serde_json::json;

const DENIED: u16 = ErrorCode::Denied as u16;
const LOCKED: u16 = ErrorCode::VaultLocked as u16;
const EXPIRED: u16 = ErrorCode::Expired as u16;
const CANCELLED: u16 = ErrorCode::Cancelled as u16;
const NOT_PAIRED: u16 = ErrorCode::NotPaired as u16;
const NOT_FOUND: u16 = ErrorCode::AccountNotFound as u16;
const INVALID_PARAMS: u16 = ErrorCode::InvalidParams as u16;

// =========================================================================================
// the happy path: pair, approve once, remember
// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_pairing_and_signing_end_to_end() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let acct = &accts[0];

    // Unpaired client: connecting works, doing anything does not.
    let (id, mut sc) = client(&env, "OUTKAST");
    assert_eq!(sc.paired, Some(false));
    let t = spawn(move || {
        let r = sc.get_public_key(None);
        (sc, r)
    });
    let v = wait_pending(&mut c, 1).remove(0);
    assert_eq!(v.kind, PendingKind::Pair);
    assert_eq!(
        v.client.pubkey.to_string(),
        id.pubkey_hex(),
        "the prompt shows the client's key"
    );
    assert_eq!(v.client.name, "OUTKAST");
    assert_eq!(v.client.via, "local");
    let peer = v.client.peer.clone().unwrap();
    assert_eq!(peer.uid, embr_platform::paths::current_uid());
    assert!(peer.pid.is_some(), "peer hints are present (and untrusted)");
    c.decide(&v, DecisionWire::Pair { account: acct.id }, None)
        .unwrap();
    let (mut sc, pk) = t.join().unwrap();
    assert_eq!(pk.unwrap(), acct.pubkey_hex);

    // Newly paired: still nothing is auto-signed.
    let t = spawn(move || {
        let r = sc.sign_event(
            &json!({"kind": 1, "content": "hello from OUTKAST", "tags": [["t", "nostr"]]}),
            None,
        );
        (sc, r)
    });
    let v = wait_pending(&mut c, 1).remove(0);
    assert_eq!(v.kind, PendingKind::Operation);
    assert_eq!(v.operation.as_deref(), Some("sign_event"));
    let ev = v.event.clone().unwrap();
    assert_eq!(
        (ev.kind, ev.content.as_str(), ev.tags_total),
        (1, "hello from OUTKAST", 1)
    );
    assert_eq!(
        v.account.as_ref().unwrap().id,
        acct.id,
        "the prompt names the account that will sign"
    );
    c.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    let (mut sc, event) = t.join().unwrap();
    let event = event.unwrap();
    event.verify().unwrap();
    assert_eq!(event.pubkey.to_hex(), acct.pubkey_hex);
    assert_eq!(event.content, "hello from OUTKAST");

    // "Allow once" stores nothing: the next request asks again.
    let t = spawn(move || (sc.sign_event(&note("again"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    let (r, _sc) = t.join().unwrap();
    assert_eq!(code_of(r), DENIED);

    // The audit log recorded metadata only.
    let log = std::fs::read_to_string(env.data.join("audit.jsonl")).unwrap();
    assert!(
        log.contains("allowed_by_user") && log.contains("denied_by_user") && log.contains("paired")
    );
    assert!(
        !log.contains("hello from OUTKAST") && !log.contains(&event.sig.to_string()),
        "no content or signatures in the audit log"
    );
    d.shutdown().await;
}

// =========================================================================================
// default deny, authentication
// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_clients_can_do_nothing_but_ping_and_pair() {
    let env = Env::new();
    let d = boot(&env).await;
    let (_c, _accts) = vault_with_accounts(&env, 1);
    let (_, mut sc) = client(&env, "stranger");
    sc.ping().unwrap();
    assert_eq!(code_of(sc.sign_event(&note("x"), None)), NOT_PAIRED);
    assert_eq!(
        code_of(sc.nip44_encrypt(&Identity::generate().pubkey_hex(), "x", None)),
        NOT_PAIRED
    );
    assert_eq!(
        code_of(sc.nip44_decrypt(&Identity::generate().pubkey_hex(), "x", None)),
        NOT_PAIRED
    );
    assert_eq!(code_of(sc.list_accounts()), NOT_PAIRED);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_rejects_bad_proofs_replays_and_silence() {
    let env = Env::new();
    let d = boot_with(&env, |c| c.limits.handshake_secs = 1).await;
    let me = Identity::generate();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. Proof signed by another key than the one claimed.
    let mut r = Raw::connect(&env);
    let h = r.server_hello();
    let other = Identity::generate();
    let proof = embr_ipc::auth::make_proof(&other, h["nonce"].as_str().unwrap(), now).unwrap();
    r.write(&json!({"hello": {"protocol": 1, "client": {"name": "x", "pubkey": me.pubkey_hex()}, "proof": proof}}).to_string());
    assert_eq!(r.read().unwrap()["error"]["name"], "unauthenticated");

    // 2. A valid hello recorded on connection A, replayed on connection B (different nonce).
    let mut a = Raw::connect(&env);
    let ha = a.server_hello();
    let proof = embr_ipc::auth::make_proof(&me, ha["nonce"].as_str().unwrap(), now).unwrap();
    let hello_line = json!({"hello": {"protocol": 1, "client": {"name": "x", "pubkey": me.pubkey_hex()}, "proof": proof}}).to_string();
    a.write(&hello_line);
    assert_eq!(a.read().unwrap()["ok"], true);
    let mut b = Raw::connect(&env);
    b.server_hello();
    b.write(&hello_line);
    assert_eq!(
        b.read().unwrap()["error"]["name"],
        "unauthenticated",
        "replayed hello must fail"
    );

    // 3. Requests before any hello are not served; the connection is closed on malformed hello.
    let mut r = Raw::connect(&env);
    r.server_hello();
    r.write(&json!({"id": "1", "method": "ping"}).to_string());
    assert_eq!(r.read().unwrap()["ok"], false);

    // 4. Wrong protocol version, junk.
    let mut r = Raw::connect(&env);
    let h = r.server_hello();
    let proof = embr_ipc::auth::make_proof(&me, h["nonce"].as_str().unwrap(), now).unwrap();
    r.write(&json!({"hello": {"protocol": 99, "client": {"name": "x", "pubkey": me.pubkey_hex()}, "proof": proof}}).to_string());
    assert_eq!(r.read().unwrap()["error"]["name"], "invalid_request");

    // 5. A connection that never says hello is dropped at the deadline.
    let mut r = Raw::connect(&env);
    r.server_hello();
    let t0 = std::time::Instant::now();
    assert!(r.read().is_none(), "the daemon closes a silent connection");
    assert!(t0.elapsed() < Duration::from_secs(5));

    // The daemon is unaffected.
    let (_c, _a) = vault_with_accounts(&env, 1);
    let (_, mut sc) = client(&env, "fine");
    sc.ping().unwrap();
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_clock_proofs_are_rejected() {
    let env = Env::new();
    let d = boot(&env).await;
    let me = Identity::generate();
    let mut r = Raw::connect(&env);
    let h = r.server_hello();
    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600;
    let proof = embr_ipc::auth::make_proof(&me, h["nonce"].as_str().unwrap(), old).unwrap();
    r.write(&json!({"hello": {"protocol": 1, "client": {"name": "x", "pubkey": me.pubkey_hex()}, "proof": proof}}).to_string());
    assert_eq!(r.read().unwrap()["error"]["name"], "unauthenticated");
    d.shutdown().await;
}

// =========================================================================================
// permissions: sessions, expiry, persistence, revocation
// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grants_session_timed_persistent_and_revoked() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (id, mut sc) = pair(&env, &mut c, &accts[0], "app");

    // --- allow for the session: immediate afterwards, but only for this connection.
    let t = spawn(move || (sc.sign_event(&note("1"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::AllowSession, exact_kind(1))
        .unwrap();
    let (r, mut sc) = t.join().unwrap();
    r.unwrap();
    sc.sign_event(&note("2"), None).unwrap(); // no prompt
    assert!(c.pending().unwrap().is_empty());
    let mut other = embr_client::SignerClient::connect(&id, opts(&env, "app")).unwrap();
    assert_eq!(other.paired, Some(true));
    let t = spawn(move || (other.sign_event(&note("3"), None), other));
    let v = wait_pending(&mut c, 1).remove(0); // a new session must ask again
    c.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    assert_eq!(code_of(t.join().unwrap().0), DENIED);
    drop(sc);

    // --- allow until a time: works, then expires.
    let (id, mut sc) = pair(&env, &mut c, &accts[0], "timed");
    let until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    let t = spawn(move || (sc.sign_event(&note("t"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::AllowUntil { until }, exact_kind(1))
        .unwrap();
    let (r, mut sc) = t.join().unwrap();
    r.unwrap();
    sc.sign_event(&note("t2"), None).unwrap();
    std::thread::sleep(Duration::from_millis(2300));
    let t = spawn(move || (sc.sign_event(&note("t3"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0); // expired: asks again
    c.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    assert_eq!(code_of(t.join().unwrap().0), DENIED);

    // --- persistent, exact kind: other kinds still ask; survives a daemon restart; revocable.
    let mut sc = embr_client::SignerClient::connect(&id, opts(&env, "timed")).unwrap();
    let t = spawn(move || (sc.sign_event(&note("p"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::AllowPersistent, exact_kind(1))
        .unwrap();
    let (r, mut sc) = t.join().unwrap();
    r.unwrap();
    let t = spawn(move || (sc.sign_event(&json!({"kind": 7, "content": "+"}), None), sc));
    let v = wait_pending(&mut c, 1).remove(0); // different kind: asks
    assert_eq!(v.event.as_ref().unwrap().kind, 7);
    c.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    assert_eq!(code_of(t.join().unwrap().0), DENIED);
    drop(c);
    d.shutdown().await;

    let d = boot(&env).await;
    let mut c = ctl(&env);
    assert_eq!(
        c.status().unwrap().vault,
        VaultState::Locked,
        "a restarted daemon starts locked"
    );
    let mut sc = embr_client::SignerClient::connect(&id, opts(&env, "timed")).unwrap();
    assert!(
        sc.locked && sc.paired.is_none(),
        "while locked the daemon cannot say whether a client is paired"
    );
    assert_eq!(code_of(sc.sign_event(&note("x"), None)), LOCKED);
    c.unlock(PW).unwrap();
    let mut sc = embr_client::SignerClient::connect(&id, opts(&env, "timed")).unwrap();
    assert_eq!(
        sc.paired,
        Some(true),
        "pairing survives restarts (stored encrypted in the vault)"
    );
    sc.sign_event(&note("after restart"), None).unwrap(); // the persistent grant is still there

    let grants: Vec<embr_policy::Grant> =
        serde_json::from_value(c.call("list_grants", json!({})).unwrap()).unwrap();
    assert_eq!(grants.len(), 1);
    c.call("revoke_grant", json!({"id": grants[0].id.0}))
        .unwrap();
    let t = spawn(move || (sc.sign_event(&note("revoked"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::AlwaysReject, exact_kind(1))
        .unwrap();
    let (r, mut sc) = t.join().unwrap();
    assert_eq!(code_of(r), DENIED);
    // "Always reject" is remembered and answered without a prompt.
    assert_eq!(code_of(sc.sign_event(&note("again"), None)), DENIED);
    assert!(c.pending().unwrap().is_empty());

    // Revoking the client forgets it entirely.
    let key = id.pubkey_hex();
    c.call("revoke_client", json!({"key": key})).unwrap();
    assert_eq!(code_of(sc.sign_event(&note("x"), None)), NOT_PAIRED);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_client_cannot_even_connect() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (id, mut sc) = pair(&env, &mut c, &accts[0], "bad app");
    c.call("block_client", json!({"key": id.pubkey_hex()}))
        .unwrap();
    assert_eq!(code_of(sc.sign_event(&note("x"), None)), DENIED);
    match embr_client::SignerClient::connect(&id, opts(&env, "bad app")) {
        Err(ClientError::Rpc(e)) => assert_eq!(e.code, DENIED),
        other => panic!("expected denial, got {other:?}"),
    }
    // Blocking during a pairing prompt rejects it and every other pending request of that key.
    let (_c2, mut sc2) = client(&env, "annoying");
    let id2 = Identity::generate();
    drop(sc2.ping());
    let mut sc3 = embr_client::SignerClient::connect(&id2, opts(&env, "annoying")).unwrap();
    let t = spawn(move || sc3.get_public_key(None));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::BlockClient, None).unwrap();
    assert_eq!(code_of(t.join().unwrap()), DENIED);
    d.shutdown().await;
}

// =========================================================================================
// isolation and escalation
// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accounts_and_clients_are_isolated() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 2);
    let (a, b) = (&accts[0], &accts[1]);
    let (_ida, mut ca) = pair(&env, &mut c, a, "client A");
    let (_idb, mut cb) = pair(&env, &mut c, b, "client B");

    // Client A cannot sign as B — and cannot tell whether B exists: same error as for a made-up key.
    let r1 = ca.sign_event(&note("x"), Some(&b.pubkey_hex));
    let r2 = ca.sign_event(&note("x"), Some(&Identity::generate().pubkey_hex()));
    assert_eq!(code_of(r1), NOT_FOUND);
    assert_eq!(code_of(r2), NOT_FOUND);
    assert_eq!(
        ca.list_accounts().unwrap().len(),
        1,
        "A only sees its own account"
    );
    assert_eq!(code_of(ca.get_public_key(Some(&b.pubkey_hex))), NOT_FOUND);

    // A persistent grant given to A does not apply to B (same kind, different client/account).
    let t = spawn(move || (ca.sign_event(&note("a"), None), ca));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::AllowPersistent, exact_kind(1))
        .unwrap();
    let (ev, mut ca) = t.join().unwrap();
    assert_eq!(ev.unwrap().pubkey.to_hex(), a.pubkey_hex);
    ca.sign_event(&note("a2"), None).unwrap();
    let t = spawn(move || (cb.sign_event(&note("b"), None), cb));
    let v = wait_pending(&mut c, 1).remove(0);
    assert_eq!(v.account.as_ref().unwrap().id, b.id);
    c.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    assert_eq!(t.join().unwrap().0.unwrap().pubkey.to_hex(), b.pubkey_hex);

    // A template claiming another author is refused before any prompt exists.
    assert_eq!(
        code_of(ca.sign_event(
            &json!({"kind": 1, "content": "x", "pubkey": b.pubkey_hex}),
            None
        )),
        INVALID_PARAMS
    );
    assert!(c.pending().unwrap().is_empty());

    // Removing an account cancels its pending requests and revokes access.
    let t = spawn(move || (ca.sign_event(&json!({"kind": 7, "content": "+"}), None), ca));
    wait_pending(&mut c, 1);
    c.call(
        "remove_account",
        json!({"id": a.id.to_string(), "confirm": true}),
    )
    .unwrap();
    let (r, mut ca) = t.join().unwrap();
    assert_eq!(code_of(r), CANCELLED);
    assert_eq!(code_of(ca.sign_event(&note("x"), None)), NOT_FOUND);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn decrypt_is_never_implied_by_signing_and_sensitive_grants_are_refused() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (_id, mut sc) = pair(&env, &mut c, &accts[0], "app");
    let peer = Identity::generate();
    let peer_hex = peer.pubkey_hex();

    // A persistent signing grant exists...
    let t = spawn(move || (sc.sign_event(&note("x"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::AllowPersistent, exact_kind(1))
        .unwrap();
    let (r, mut sc) = t.join().unwrap();
    r.unwrap();

    // ...but decrypting still asks, is flagged as revealing plaintext, and legacy NIP-04 is flagged.
    let ct = peer
        .nip44_encrypt(
            &accts[0]
                .pubkey_hex
                .parse::<embr_crypto::PublicKey>()
                .unwrap(),
            "private words",
            &Limits::default(),
        )
        .unwrap();
    let (ph, ct2) = (peer_hex.clone(), ct.clone());
    let t = spawn(move || (sc.nip44_decrypt(&ph, &ct2, None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    assert!(v.reveals_plaintext && !v.legacy);
    assert_eq!(v.peer.unwrap().to_string(), peer_hex);
    // Too broad (no peer, persistent): refused, and the request stays pending for another choice.
    let broad = Some(ScopeWire {
        kind: KindScope::Any,
        peer: None,
        uses: None,
    });
    let err = c
        .decide(&v, DecisionWire::AllowPersistent, broad)
        .unwrap_err();
    assert!(
        matches!(&err, ClientError::Rpc(e) if e.code == INVALID_PARAMS),
        "{err:?}"
    );
    assert_eq!(c.pending().unwrap().len(), 1);
    c.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    let (r, mut sc) = t.join().unwrap();
    assert_eq!(r.unwrap(), "private words");

    // NIP-04 decrypt shows as legacy.
    let c04 = peer
        .nip04_encrypt(
            &accts[0]
                .pubkey_hex
                .parse::<embr_crypto::PublicKey>()
                .unwrap(),
            "old",
            &Limits::default(),
        )
        .unwrap();
    let ph = peer_hex.clone();
    let t = spawn(move || (sc.nip04_decrypt(&ph, &c04, None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    assert!(v.legacy && v.reveals_plaintext);
    c.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    let (r, mut sc) = t.join().unwrap();
    assert_eq!(r.unwrap(), "old");

    // Direct-message kinds cannot be remembered, only allowed once or for the session.
    let t = spawn(move || {
        (
            sc.sign_event(&json!({"kind": 14, "content": "dm"}), None),
            sc,
        )
    });
    let v = wait_pending(&mut c, 1).remove(0);
    assert!(v.event.as_ref().unwrap().sensitive);
    for choice in [
        DecisionWire::AllowPersistent,
        DecisionWire::AllowUntil {
            until: u64::MAX / 2,
        },
    ] {
        let e = c.decide(&v, choice, exact_kind(14)).unwrap_err();
        assert!(
            matches!(&e, ClientError::Rpc(r) if r.code == INVALID_PARAMS),
            "{e:?}"
        );
    }
    c.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    t.join().unwrap().0.unwrap();

    // A decision must echo the digest of what was reviewed.
    let (_i2, mut sc2) = pair(&env, &mut c, &accts[0], "second");
    let t = spawn(move || (sc2.sign_event(&note("real"), None), sc2));
    let mut v = wait_pending(&mut c, 1).remove(0);
    let real_digest = v.digest.clone();
    v.digest = "00".repeat(32);
    let e = c.decide(&v, DecisionWire::AllowOnce, None).unwrap_err();
    assert!(matches!(&e, ClientError::Rpc(r) if r.code == INVALID_PARAMS));
    v.digest = real_digest;
    c.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    assert_eq!(code_of(t.join().unwrap().0), DENIED);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompts_show_sanitised_content_and_encryption_works() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (_id, mut sc) = pair(&env, &mut c, &accts[0], "evil\u{202e}app");
    let peer = Identity::generate();
    let peer_pub = peer.public_key();
    let ph = peer.pubkey_hex();
    let t = spawn(move || {
        (sc.sign_event(&json!({"kind": 1, "content": "pay to \u{202e}gnp.exe\u{200b}", "tags": [["p", "x\u{200b}y"]]}), None), sc)
    });
    let v = wait_pending(&mut c, 1).remove(0);
    assert!(v.client.name.contains("⟦U+202E⟧") && !v.client.name.contains('\u{202e}'));
    let ev = v.event.clone().unwrap();
    assert!(ev.content.contains("⟦U+202E⟧") && ev.content.contains("⟦U+200B⟧"));
    assert!(ev.tags[0][1].contains("⟦U+200B⟧"));
    c.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    let (r, mut sc) = t.join().unwrap();
    assert_eq!(code_of(r), DENIED);
    // A BEL (an ambiguous C0 control) in a tag is refused before any prompt exists.
    let r = sc.sign_event(
        &json!({"kind": 1, "content": "x", "tags": [["p", "x\u{0007}y"]]}),
        None,
    );
    assert_eq!(code_of(r), INVALID_PARAMS);
    assert!(c.pending().unwrap().is_empty());

    // NIP-44 / NIP-04 encryption by the signer decrypts for the peer.
    let ph2 = ph.clone();
    let t = spawn(move || (sc.nip44_encrypt(&ph2, "hello peer", None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    assert_eq!(v.text_preview.as_deref(), Some("hello peer"));
    c.decide(&v, DecisionWire::AllowPersistent, None).unwrap();
    let (ct, mut sc) = t.join().unwrap();
    let author: embr_crypto::PublicKey = accts[0].pubkey_hex.parse().unwrap();
    assert_eq!(
        &*peer
            .nip44_decrypt(&author, &ct.unwrap(), &Limits::default())
            .unwrap(),
        "hello peer"
    );
    // Encryption was remembered for this peer.
    let ct = sc.nip44_encrypt(&ph, "second", None).unwrap();
    assert_eq!(
        &*peer
            .nip44_decrypt(&author, &ct, &Limits::default())
            .unwrap(),
        "second"
    );
    let _ = peer_pub;
    d.shutdown().await;
}

// =========================================================================================
// lock state
// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locking_cancels_pending_requests_and_blocks_everything() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (_id, mut sc) = pair(&env, &mut c, &accts[0], "app");
    let token = c.token.clone().unwrap();

    let t = spawn(move || (sc.sign_event(&note("x"), None), sc));
    wait_pending(&mut c, 1);
    let mut events = ctl(&env);
    events.authenticate(&token).unwrap();
    events.subscribe().unwrap();
    c.call("lock", json!({})).unwrap();
    let (r, mut sc) = t.join().unwrap();
    assert_eq!(
        code_of(r),
        CANCELLED,
        "a lock resolves pending requests instead of leaving them hanging"
    );
    assert_eq!(code_of(sc.sign_event(&note("x"), None)), LOCKED);
    assert_eq!(code_of(sc.get_public_key(None)), LOCKED);
    sc.ping().unwrap();

    // Everything in memory is gone.
    {
        let g = d.shared.lock();
        assert_eq!(g.vault_state(), VaultState::Locked);
        assert!(g.policy.clients().is_empty() && g.policy.grants().is_empty());
        assert!(g.pending.is_empty());
    }
    // The old control token no longer works, and neither do open authenticated connections.
    let mut c2 = ctl(&env);
    assert!(c2.authenticate(&token).is_err());
    assert!(
        matches!(c.call("list_accounts", json!({})), Err(ClientError::Rpc(e)) if e.code == ErrorCode::Unauthenticated as u16)
    );
    // Subscribers were told.
    let mut saw_lock = false;
    events
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    while let Ok(Some(ev)) = events.next_event() {
        saw_lock |= ev == ControlEvent::Locked;
        if saw_lock {
            break;
        }
    }
    assert!(saw_lock);

    // Unlocking restores service, including the stored pairing.
    c2.unlock(PW).unwrap();
    assert_eq!(
        c2.call("list_accounts", json!({})).unwrap()["accounts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gui_restart_while_the_daemon_stays_unlocked() {
    let env = Env::new();
    let d = boot_with(&env, |c| c.limits.unlock_free_attempts = 2).await;
    let (mut gui, accts) = vault_with_accounts(&env, 1);
    let token = gui.token.clone().unwrap();
    let (_id, mut sc) = pair(&env, &mut gui, &accts[0], "app");
    let t = spawn(move || (sc.sign_event(&note("x"), None), sc));
    wait_pending(&mut gui, 1);
    drop(gui); // the GUI quits with a request pending

    // The daemon keeps serving; a new GUI re-attaches with the token and sees the request.
    let mut gui2 = ctl(&env);
    assert_eq!(
        gui2.status().unwrap().vault,
        VaultState::Unlocked,
        "status needs no authentication"
    );
    assert!(
        matches!(gui2.call("list_pending", json!({})), Err(ClientError::Rpc(e)) if e.code == ErrorCode::Unauthenticated as u16)
    );
    assert!(gui2.authenticate("00".repeat(32).as_str()).is_err());
    gui2.authenticate(&token).unwrap();
    let v = wait_pending(&mut gui2, 1).remove(0);
    gui2.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    t.join().unwrap().0.unwrap();

    // Wrong passwords are throttled (after the free attempts), and the throttle hurts the guesser, not the real user.
    let mut atk = ctl(&env);
    for _ in 0..2 {
        assert!(
            matches!(atk.unlock("wrong wrong wrong"), Err(ClientError::Rpc(e)) if e.code == ErrorCode::Unauthenticated as u16)
        );
    }
    assert!(
        matches!(atk.unlock("wrong wrong wrong"), Err(ClientError::Rpc(e)) if e.code == ErrorCode::Unauthenticated as u16)
    );
    match atk.unlock(PW) {
        Err(ClientError::Rpc(e)) => assert_eq!(
            e.code,
            ErrorCode::RateLimited as u16,
            "throttled even with the right password"
        ),
        other => panic!("expected throttling, got {other:?}"),
    }
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_auto_lock_follows_user_activity_not_client_traffic() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (_id, mut sc) = pair(&env, &mut c, &accts[0], "app");
    let t = spawn(move || (sc.sign_event(&note("x"), None), sc));
    let v = wait_pending(&mut c, 1).remove(0);
    c.decide(&v, DecisionWire::AllowPersistent, exact_kind(1))
        .unwrap();
    let (r, mut sc) = t.join().unwrap();
    r.unwrap();

    // Settings validation: nonsense is refused; a short timeout is injected directly for the test.
    assert!(
        c.call(
            "set_settings",
            json!({"lock_timeout_secs": 5, "notifications": true, "remote_signing_enabled": false})
        )
        .is_err()
    );
    {
        let mut g = d.shared.lock();
        g.settings.lock_timeout_secs = 2;
        g.touch_activity();
    }
    d.shared.activity.notify_one();

    // Auto-allowed client traffic every 300 ms must NOT keep the vault open.
    let start = std::time::Instant::now();
    let mut locked_after = None;
    while start.elapsed() < Duration::from_secs(5) {
        match sc.sign_event(&note("keepalive"), None) {
            Ok(_) => std::thread::sleep(Duration::from_millis(300)),
            Err(ClientError::Rpc(e)) if e.code == LOCKED => {
                locked_after = Some(start.elapsed());
                break;
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    let after = locked_after.expect("the vault must lock itself after the idle timeout");
    assert!(
        after >= Duration::from_millis(1800) && after < Duration::from_millis(3500),
        "locked after {after:?}"
    );
    assert_eq!(c.status().unwrap().vault, VaultState::Locked);
    d.shutdown().await;
}

// =========================================================================================
// malformed IPC, abuse, concurrency
// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_and_hostile_ipc_is_contained() {
    let env = Env::new();
    let d = boot(&env).await;
    let (_c, _a) = vault_with_accounts(&env, 1);
    let me = Identity::generate();
    let mut r = Raw::connect(&env);
    assert_eq!(r.login(&me)["ok"], true);

    let name_of = |v: serde_json::Value| v["error"]["name"].as_str().unwrap_or("").to_owned();
    let mut pings = 0;
    // Garbage / wrong shape / unknown fields / bad ids / non-object params.
    for (line, expect) in [
        ("{not json", "invalid_request"),
        ("[]", "invalid_request"),
        (r#"{"id":"1"}"#, "invalid_request"),
        (
            r#"{"id":"1","method":"ping","admin":true}"#,
            "invalid_request",
        ),
        (r#"{"id":7,"method":"ping"}"#, "invalid_request"),
        (r#"{"id":"has space","method":"ping"}"#, "invalid_request"),
        (
            r#"{"id":"2","method":"sign_event","params":[]}"#,
            "not_paired",
        ),
    ] {
        r.write(line);
        assert_eq!(name_of(r.read().unwrap()), expect, "{line}");
        // A valid request in between resets the "five malformed lines in a row" counter.
        pings += 1;
        r.write(&json!({"id": format!("ok{pings}"), "method": "ping"}).to_string());
        assert_eq!(r.read().unwrap()["result"], "pong");
    }
    // Unknown and foreign methods (including control-channel methods) are unsupported here.
    for m in [
        "nope",
        "decide",
        "unlock",
        "list_pending",
        "lock",
        "reveal_nsec",
        "export_backup",
    ] {
        r.write(&json!({"id": format!("m-{m}"), "method": m}).to_string());
        assert_eq!(name_of(r.read().unwrap()), "unsupported_method", "{m}");
    }
    // Replay of a used id.
    r.write(&json!({"id": "dup", "method": "ping"}).to_string());
    assert_eq!(r.read().unwrap()["result"], "pong");
    r.write(&json!({"id": "dup", "method": "ping"}).to_string());
    assert_eq!(name_of(r.read().unwrap()), "invalid_request");
    // `cancel` of nothing.
    r.write(&json!({"id": "c1", "method": "cancel", "params": {"id": "nothing"}}).to_string());
    assert_eq!(name_of(r.read().unwrap()), "invalid_params");

    // Five malformed lines in a row end the connection.
    let mut r2 = Raw::connect(&env);
    r2.login(&me);
    for _ in 0..5 {
        r2.write("garbage");
        let _ = r2.read();
    }
    r2.write(&json!({"id": "x", "method": "ping"}).to_string());
    assert!(r2.read().is_none());

    // A NUL byte and a >1 MiB line.
    let mut r3 = Raw::connect(&env);
    r3.login(&me);
    r3.write("{\"id\":\"1\",\"method\":\"pi\0ng\"}");
    assert!(r3.read().is_none(), "NUL in a line closes the connection");
    let mut r4 = Raw::connect(&env);
    r4.login(&me);
    let huge = format!(
        "{{\"id\":\"1\",\"method\":\"ping\",\"params\":{{\"x\":\"{}\"}}}}",
        "a".repeat(1_100_000)
    );
    r4.write(&huge);
    assert_eq!(name_of(r4.read().unwrap()), "payload_too_large");
    assert!(r4.read().is_none(), "and the connection is closed");

    // A client that sends nothing but junk to an unauthenticated slot does not exhaust the daemon.
    let (_id, mut sc) = client(&env, "still works");
    sc.ping().unwrap();
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limits_pending_caps_expiry_and_cancel() {
    let env = Env::new();
    let d = boot_with(&env, |c| {
        c.limits.pending_per_client = 2;
        c.limits.rate_burst = 6;
        c.limits.rate_per_sec = 1;
    })
    .await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (id, mut sc) = pair(&env, &mut c, &accts[0], "app"); // used ~2 of the burst
    drop(sc.ping());

    // Pending cap per client: the third concurrent prompt is refused immediately.
    let mut conns: Vec<_> = (0..3)
        .map(|_| embr_client::SignerClient::connect(&id, opts(&env, "app")).unwrap())
        .collect();
    let c3 = conns.pop().unwrap();
    let mut threads = Vec::new();
    for mut cn in conns {
        threads.push(spawn(move || {
            cn.sign_event(&json!({"kind": 1, "content": "q"}), None)
        }));
    }
    wait_pending(&mut c, 2);
    let mut c3 = c3;
    assert_eq!(
        code_of(c3.sign_event(&note("third"), None)),
        ErrorCode::RateLimited as u16
    );
    for v in c.pending().unwrap() {
        c.decide(&v, DecisionWire::RejectOnce, None).unwrap();
    }
    for t in threads {
        assert_eq!(code_of(t.join().unwrap()), DENIED);
    }

    // Rate limit: hammering exhausts the token bucket and says when to retry.
    let mut limited = None;
    for _ in 0..30 {
        if let Err(ClientError::Rpc(e)) = sc.call("ping", json!({})) {
            limited = Some(e);
            break;
        }
    }
    let e = limited.expect("a burst of pings must be rate limited");
    assert_eq!(e.code, ErrorCode::RateLimited as u16);
    assert!(e.data.unwrap()["retry_after_ms"].as_u64().unwrap() > 0);
    d.shutdown().await;

    // Expiry: a request nobody answers times out and leaves no pending entry.
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let (_id, mut sc) = pair(&env, &mut c, &accts[0], "app");
    let r = sc.call_with_timeout(
        "sign_event",
        json!({"event": {"kind": 1, "content": "slow"}}),
        Some(300),
    );
    assert_eq!(code_of(r), EXPIRED);
    assert!(c.pending().unwrap().is_empty());

    // Cancel: a second line on the same connection withdraws the first request.
    let mut raw = Raw::connect(&env);
    let key = Identity::generate();
    raw.login(&key);
    // (an unpaired client's get_public_key blocks on a pairing prompt)
    raw.write(&json!({"id": "a", "method": "get_public_key"}).to_string());
    wait_pending(&mut c, 1);
    raw.write(&json!({"id": "b", "method": "cancel", "params": {"id": "a"}}).to_string());
    let mut got = std::collections::BTreeMap::new();
    for _ in 0..2 {
        let v = raw.read().unwrap();
        got.insert(v["id"].as_str().unwrap().to_owned(), v);
    }
    assert_eq!(got["b"]["result"], true);
    assert_eq!(got["a"]["error"]["name"], "cancelled");
    assert!(c.pending().unwrap().is_empty());

    // Disconnecting also withdraws pending requests.
    let mut raw = Raw::connect(&env);
    raw.login(&Identity::generate());
    raw.write(&json!({"id": "a", "method": "get_public_key"}).to_string());
    wait_pending(&mut c, 1);
    drop(raw);
    wait_no_pending(&mut c);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn many_clients_pair_and_sign_concurrently() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 2);
    const N: usize = 8;

    let mut threads = Vec::new();
    for i in 0..N {
        let (e, n) = (env.signer(), format!("client {i}"));
        threads.push(spawn(move || {
            let id = Identity::generate();
            let mut o = embr_client::ConnectOptions::new(n);
            o.endpoint = Some(e);
            let mut sc = embr_client::SignerClient::connect(&id, o).unwrap();
            let pk = sc.get_public_key(None).unwrap();
            let ev = sc
                .sign_event(&json!({"kind": 1, "content": format!("from {i}")}), None)
                .unwrap();
            ev.verify().unwrap();
            (pk, ev.pubkey.to_hex())
        }));
    }
    // Answer all pairing prompts (alternating accounts), then all signing prompts.
    let pairs = wait_pending(&mut c, N);
    assert_eq!(pairs.len(), N);
    let mut expected = std::collections::BTreeMap::new();
    for (i, v) in pairs.iter().enumerate() {
        let acct = &accts[i % 2];
        expected.insert(v.client.pubkey.to_string(), acct.pubkey_hex.clone());
        c.decide(v, DecisionWire::Pair { account: acct.id }, None)
            .unwrap();
    }
    let mut answered = 0;
    while answered < N {
        for v in wait_pending(&mut c, 1) {
            assert_eq!(v.kind, PendingKind::Operation);
            assert_eq!(
                v.account.as_ref().unwrap().pubkey_hex,
                expected[&v.client.pubkey.to_string()],
                "each prompt names the right account"
            );
            c.decide(&v, DecisionWire::AllowOnce, None).unwrap();
            answered += 1;
        }
    }
    for t in threads {
        let (pk, signer) = t.join().unwrap();
        assert_eq!(
            pk, signer,
            "every client got a signature from the account it was paired to"
        );
    }
    d.shutdown().await;
}

// =========================================================================================
// control channel, secrets, filesystem
// =========================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exports_need_the_password_and_clients_cannot_reach_the_control_channel() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, accts) = vault_with_accounts(&env, 1);
    let id = accts[0].id.to_string();

    let e = c.call("export_ncryptsec", json!({"id": id, "vault_password": "wrong wrong wrong", "export_password": "x", "log_n": 16})).unwrap_err();
    assert!(matches!(e, ClientError::Rpc(ref r) if r.code == ErrorCode::Unauthenticated as u16));
    let v = c
        .call(
            "export_ncryptsec",
            json!({"id": id, "vault_password": PW, "export_password": "export pw", "log_n": 16}),
        )
        .unwrap();
    let (back, _) = Identity::from_ncryptsec(
        v["ncryptsec"].as_str().unwrap(),
        "export pw",
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(back.pubkey_hex(), accts[0].pubkey_hex);
    let v = c
        .call("reveal_nsec", json!({"id": id, "vault_password": PW}))
        .unwrap();
    assert_eq!(
        Identity::from_secret_str(v["nsec"].as_str().unwrap())
            .unwrap()
            .pubkey_hex(),
        accts[0].pubkey_hex
    );
    // Destructive operations demand explicit confirmation.
    assert!(
        c.call("remove_account", json!({"id": id, "confirm": false}))
            .is_err()
    );

    // The control socket needs a password even to look at accounts; a signer client has no way in:
    // it would have to know the vault password.
    let mut unauth = ctl(&env);
    for m in [
        "list_accounts",
        "list_pending",
        "list_clients",
        "reveal_nsec",
        "decide",
        "lock",
        "export_backup",
    ] {
        let r = unauth.call(m, json!({}));
        assert!(
            matches!(r, Err(ClientError::Rpc(ref e)) if e.code == ErrorCode::Unauthenticated as u16),
            "{m}: {r:?}"
        );
    }
    // Backup is encrypted and restorable.
    let dest = env.tmp.path().join("backup.embr");
    c.call("export_backup", json!({"dest": dest.display().to_string()}))
        .unwrap();
    assert!(
        c.call("export_backup", json!({"dest": "relative/path"}))
            .is_err()
    );
    let restored =
        embr_vault::Vault::restore_backup(&dest, PW, env.tmp.path().join("restored.embr")).unwrap();
    assert_eq!(restored.list_accounts().unwrap().len(), 1);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_change_and_settings_persist() {
    let env = Env::new();
    let d = boot(&env).await;
    let (mut c, _a) = vault_with_accounts(&env, 1);
    c.call(
        "set_settings",
        json!({"lock_timeout_secs": 600, "notifications": false, "remote_signing_enabled": false}),
    )
    .unwrap();
    c.call(
        "change_password",
        json!({"old": PW, "new": "another long passphrase"}),
    )
    .unwrap();
    c.call("lock", json!({})).unwrap();
    let mut c2 = ctl(&env);
    assert!(c2.unlock(PW).is_err(), "the old password stops working");
    c2.unlock("another long passphrase").unwrap();
    let s = c2.call("get_settings", json!({})).unwrap();
    assert_eq!(s["lock_timeout_secs"], 600);
    assert_eq!(
        s["remote_signing_enabled"], false,
        "remote signing is off unless the user turns it on"
    );
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_instance_stale_sockets_and_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    // A leftover socket file from a crashed daemon is replaced.
    std::fs::create_dir_all(&env.run).unwrap();
    std::fs::set_permissions(&env.run, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(env.signer(), b"stale").unwrap();
    let d = boot(&env).await;

    // Second daemon for the same user: refused.
    let second = embrd::start(env.config()).await;
    assert!(matches!(second, Err(embrd::DaemonError::AlreadyRunning)));

    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&env.signer()), 0o600);
    assert_eq!(mode(&env.control()), 0o600);
    assert_eq!(mode(&env.run), 0o700);
    assert_eq!(mode(&env.data), 0o700);

    // The SDK refuses to talk through a directory other users could have prepared.
    std::fs::set_permissions(&env.run, std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = embr_client::SignerClient::connect(&Identity::generate(), opts(&env, "x"));
    assert!(
        matches!(r, Err(ClientError::Connect(ref e)) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{r:?}"
    );
    std::fs::set_permissions(&env.run, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Shutdown removes sockets and releases the lock.
    d.shutdown().await;
    assert!(!env.signer().exists() && !env.control().exists());
    let d = boot(&env).await;
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_vault_rules() {
    let env = Env::new();
    let d = boot(&env).await;
    let mut c = ctl(&env);
    assert_eq!(c.status().unwrap().vault, VaultState::Missing);
    assert!(c.unlock(PW).is_err(), "nothing to unlock yet");
    assert!(
        c.create_vault("short").is_err(),
        "password policy is enforced by the daemon"
    );
    assert_eq!(
        c.status().unwrap().vault,
        VaultState::Missing,
        "a failed create leaves no vault"
    );
    c.create_vault(PW).unwrap();
    assert!(
        ctl(&env).create_vault(PW).is_err(),
        "never overwrite an existing vault"
    );
    let status = c.status().unwrap();
    assert_eq!(status.vault, VaultState::Unlocked);
    assert!(!status.remote_signing_enabled);
    d.shutdown().await;
}
