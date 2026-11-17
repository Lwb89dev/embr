//! Interoperability: an independent NIP-46 client (nostr-tools' `BunkerSigner`, JavaScript) drives
//! the Embr daemon through a relay — both the signer-initiated (`bunker://`) and the
//! client-initiated (`nostrconnect://`) flows.
//!
//! Needs `node` and `tests/interop/node_modules` (`cd tests/interop && npm ci --ignore-scripts`).
//! Without them the test skips with a message, unless `EMBR_REQUIRE_INTEROP=1` (set by CI and by
//! `tests/interop/run.sh`), in which case it fails.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    unreachable_pub
)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::*;
use embr_core::AccountMeta;
use embr_ipc::control::{DecisionWire, Nip46Status, PendingKind};
use embr_nip46::testing::{Options, TestRelay};
use serde_json::{Value, json};

fn interop_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/interop")
}

fn available() -> bool {
    let ok = Command::new("node").arg("--version").output().is_ok()
        && interop_dir().join("node_modules/nostr-tools").exists();
    if !ok {
        assert!(
            std::env::var_os("EMBR_REQUIRE_INTEROP").is_none(),
            "interop prerequisites are missing but EMBR_REQUIRE_INTEROP is set"
        );
        eprintln!(
            "SKIPPED: node or tests/interop/node_modules not available (run `npm ci --ignore-scripts` in tests/interop)"
        );
    }
    ok
}

async fn wait_connected(c: &mut embr_client::control::ControlClient) {
    for _ in 0..400 {
        let s: Nip46Status =
            serde_json::from_value(c.call("nip46_status", json!({})).unwrap()).unwrap();
        if !s.relays.is_empty() && s.relays.iter().all(|r| r.state == "connected") {
            tokio::time::sleep(Duration::from_millis(200)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("relay never connected");
}

struct Rig {
    daemon: embrd::DaemonHandle,
    relay: TestRelay,
    ctl: embr_client::control::ControlClient,
    account: AccountMeta,
}

async fn rig() -> Rig {
    let env = Env::new();
    let daemon = boot(&env).await;
    let relay = TestRelay::start(Options::default()).await;
    let (mut ctl, accounts) = vault_with_accounts(&env, 1);
    ctl.call("set_settings", json!({"lock_timeout_secs": 900, "notifications": true, "remote_signing_enabled": true, "relays": [relay.url()]})).unwrap();
    wait_connected(&mut ctl).await;
    std::mem::forget(env); // keep the temp dir alive for the daemon's lifetime (cleaned by the OS)
    Rig {
        daemon,
        relay,
        ctl,
        account: accounts[0].clone(),
    }
}

/// Spawns the node client and returns a channel of its JSON lines.
fn spawn_node(mode: &str, arg: &str) -> (std::process::Child, mpsc::Receiver<Value>) {
    let mut child = Command::new("node")
        .current_dir(interop_dir())
        .args(["nip46_client.mjs", mode, arg])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                let _ = tx.send(v);
            }
        }
    });
    (child, rx)
}

/// Approves whatever the daemon asks until the node client reports `done`; returns all node events.
fn drive(
    rig: &mut Rig,
    child: &mut std::process::Child,
    rx: &mpsc::Receiver<Value>,
    mut events: Vec<Value>,
) -> Vec<Value> {
    let start = Instant::now();
    let mut approved: Vec<String> = Vec::new();
    loop {
        while let Ok(v) = rx.try_recv() {
            events.push(v);
        }
        if events.iter().any(|e| e["event"] == "done") {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "interop run timed out; node said: {events:?}; approved: {approved:?}"
        );
        if let Some(status) = child.try_wait().unwrap() {
            while let Ok(v) = rx.try_recv() {
                events.push(v);
            }
            assert!(
                status.success() || events.iter().any(|e| e["event"] == "done"),
                "node client failed ({status}); events: {events:?}"
            );
            break;
        }
        for v in rig.ctl.pending().unwrap() {
            let d = match v.kind {
                PendingKind::Pair => DecisionWire::Pair {
                    account: rig.account.id,
                },
                PendingKind::Operation => DecisionWire::AllowOnce,
            };
            assert_eq!(v.client.via, "nip46");
            approved.push(format!(
                "{} {:?}",
                v.operation.clone().unwrap_or_else(|| "pair".into()),
                v.kind
            ));
            rig.ctl.decide(&v, d, None).unwrap();
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "node client exited with {status}; events: {events:?}"
    );
    events
}

fn assert_full_session(events: &[Value], account: &AccountMeta) {
    let find = |name: &str| {
        events
            .iter()
            .find(|e| e["event"] == name)
            .unwrap_or_else(|| panic!("node never reported `{name}`: {events:?}"))
    };
    find("connected");
    assert_eq!(
        find("pubkey")["pubkey"],
        account.pubkey_hex,
        "nostr-tools got the *user* pubkey, not the transport key"
    );
    let signed = find("signed");
    assert_eq!(signed["pubkey"], account.pubkey_hex);
    assert_eq!(find("encrypted")["ok"], true);
    find("pinged");
    find("done");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn nostr_tools_client_via_bunker_uri() {
    if !available() {
        return;
    }
    let mut rig = rig().await;
    let v = rig
        .ctl
        .call(
            "nip46_bunker",
            json!({"account": rig.account.id.to_string()}),
        )
        .unwrap();
    let uri = v["uri"].as_str().unwrap().to_owned();
    wait_connected(&mut rig.ctl).await;
    let (mut child, rx) = spawn_node("bunker", &uri);
    let events = drive(&mut rig, &mut child, &rx, Vec::new());
    assert_full_session(&events, &rig.account);
    // The signer's relay traffic never contained plaintext.
    for ev in rig.relay.events() {
        assert!(
            !ev.content.contains("hello from nostr-tools") && !ev.content.contains("secret from")
        );
    }
    rig.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn nostr_tools_client_via_nostrconnect_uri() {
    if !available() {
        return;
    }
    let mut rig = rig().await;
    let (mut child, rx) = spawn_node("nostrconnect", &rig.relay.url());
    // First line from node is the URI the *client* created; import it into Embr.
    let first = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("node did not print its nostrconnect URI");
    assert_eq!(first["event"], "uri");
    let uri = first["uri"].as_str().unwrap().to_owned();
    rig.ctl
        .call(
            "nip46_connect",
            json!({"uri": uri, "account": rig.account.id.to_string()}),
        )
        .unwrap();
    let events = drive(&mut rig, &mut child, &rx, vec![first]);
    assert_full_session(&events, &rig.account);
    rig.daemon.shutdown().await;
}
