//! Windows: the daemon on real named pipes (user-only DACL), the SDK and the control client.
//! Compiled and run only on Windows (the Linux/macOS suites cover the same behaviour on Unix sockets).
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    unreachable_pub
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use embr_client::control::ControlClient;
use embr_client::{ConnectOptions, SignerClient};
use embr_crypto::Identity;
use embr_ipc::control::DecisionWire;
use embr_vault::KdfParams;
use serde_json::json;

const PW: &str = "correct horse battery staple";

fn unique() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn config(tmp: &std::path::Path, tag: &str) -> (embrd::DaemonConfig, PathBuf, PathBuf) {
    let mut cfg = embrd::DaemonConfig::from_environment();
    cfg.data_dir = tmp.join("data");
    cfg.runtime_dir = tmp.join(format!("run-{tag}"));
    let signer = PathBuf::from(format!(r"\\.\pipe\embr-test-signer-{}", unique_name()));
    let control = PathBuf::from(format!(r"\\.\pipe\embr-test-control-{}", unique_name()));
    cfg.signer_socket = signer.clone();
    cfg.control_socket = control.clone();
    cfg.kdf = KdfParams::MINIMUM;
    cfg.harden = false;
    (cfg, signer, control)
}

fn unique_name() -> String {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "{}-{}",
        unique(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

fn wait_pending(c: &mut ControlClient) -> embr_ipc::control::PendingView {
    let start = Instant::now();
    loop {
        if let Some(v) = c.pending().unwrap().into_iter().next() {
            return v;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "no pending request appeared"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_signing_and_locking_over_named_pipes() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, signer, control) = config(tmp.path(), "a");
    let daemon = embrd::start(cfg).await.unwrap();

    let mut c = ControlClient::connect(Some(control)).unwrap();
    c.create_vault(PW).unwrap();
    let acct: embr_core::AccountMeta =
        serde_json::from_value(c.call("add_generated", json!({"label": "main"})).unwrap()).unwrap();

    let id = Identity::generate();
    let mut opts = ConnectOptions::new("Windows smoke test");
    opts.endpoint = Some(signer.clone());
    let mut sc = SignerClient::connect(&id, opts).unwrap();
    assert_eq!(sc.paired, Some(false));
    let t = std::thread::spawn(move || {
        let pk = sc.get_public_key(None);
        (sc, pk)
    });
    let v = wait_pending(&mut c);
    assert!(
        v.client.peer.is_some(),
        "the pipe client's pid is reported as a hint"
    );
    c.decide(&v, DecisionWire::Pair { account: acct.id }, None)
        .unwrap();
    let (mut sc, pk) = t.join().unwrap();
    assert_eq!(pk.unwrap(), acct.pubkey_hex);

    let t = std::thread::spawn(move || {
        let ev = sc.sign_event(&json!({"kind": 1, "content": "hello from Windows"}), None);
        (sc, ev)
    });
    let v = wait_pending(&mut c);
    assert_eq!(v.event.as_ref().unwrap().content, "hello from Windows");
    c.decide(&v, DecisionWire::AllowOnce, None).unwrap();
    let (mut sc, ev) = t.join().unwrap();
    let ev = ev.unwrap();
    ev.verify().unwrap();
    assert_eq!(ev.pubkey.to_hex(), acct.pubkey_hex);

    // Unauthenticated control connections get nothing; locking works and is enforced.
    let mut anon = ControlClient::connect(Some(PathBuf::from(
        daemon.shared.cfg.control_socket.clone(),
    )))
    .unwrap();
    assert!(anon.call("list_accounts", json!({})).is_err());
    c.call("lock", json!({})).unwrap();
    assert!(
        sc.sign_event(&json!({"kind": 1, "content": "x"}), None)
            .is_err()
    );
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_squatted_pipe_name_stops_the_daemon_from_starting() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg_a, _, _) = config(tmp.path(), "a");
    let daemon = embrd::start(cfg_a.clone()).await.unwrap();
    // A second daemon (different instance lock) asking for the same pipe names must fail
    // (FILE_FLAG_FIRST_PIPE_INSTANCE), not silently share or take over the endpoint.
    let mut cfg_b = cfg_a.clone();
    cfg_b.runtime_dir = tmp.path().join("run-b");
    let second = embrd::start(cfg_b).await;
    assert!(second.is_err(), "the pipe name was already taken");
    daemon.shutdown().await;
}
