//! The CLI against a real daemon: vault creation, accounts, terminal approvals.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use embr_client::{ConnectOptions, SignerClient};
use embr_crypto::Identity;
use serde_json::json;

const PW: &str = "correct horse battery staple";

struct Env {
    _tmp: tempfile::TempDir,
    control: std::path::PathBuf,
    signer: std::path::PathBuf,
}

fn env() -> (Env, embrd::DaemonConfig) {
    let tmp = tempfile::Builder::new().prefix("c").tempdir().unwrap();
    let mut cfg = embrd::DaemonConfig::from_environment();
    cfg.runtime_dir = tmp.path().join("r");
    cfg.data_dir = tmp.path().join("d");
    cfg.signer_socket = cfg.runtime_dir.join("signer.sock");
    cfg.control_socket = cfg.runtime_dir.join("control.sock");
    cfg.kdf = embr_vault::KdfParams::MINIMUM;
    cfg.harden = false;
    (
        Env {
            control: cfg.control_socket.clone(),
            signer: cfg.signer_socket.clone(),
            _tmp: tmp,
        },
        cfg,
    )
}

/// Runs `embrctl` with `stdin` as its standard input.
fn ctl(env: &Env, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_embrctl"))
        .arg("--control-socket")
        .arg(&env.control)
        .arg("--password-stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    // Never wait forever for the CLI: a hang must fail this test, by name, instead of stalling CI.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("`embrctl {}` did not finish within 60 s", args.join(" "));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_manages_the_vault_and_answers_approvals() {
    let (env, cfg) = env();
    let daemon = embrd::start(cfg).await.unwrap();

    let o = ctl(&env, &["status"], "");
    assert!(
        o.status.success() && out(&o).contains("Missing"),
        "{}",
        out(&o)
    );
    let o = ctl(&env, &["accounts"], &format!("{PW}\n"));
    assert!(
        !o.status.success() && err(&o).contains("embrctl init"),
        "{}",
        err(&o)
    );

    assert!(ctl(&env, &["init"], &format!("{PW}\n")).status.success());
    let o = ctl(&env, &["accounts", "add", "main"], &format!("{PW}\n"));
    assert!(o.status.success(), "{}", err(&o));
    let o = ctl(&env, &["accounts"], &format!("{PW}\n"));
    assert!(
        out(&o).contains("main") && out(&o).contains("npub1") && out(&o).contains('*'),
        "{}",
        out(&o)
    );

    // A wrong password fails cleanly and says so.
    let o = ctl(&env, &["accounts"], "not the password!!\n");
    assert!(
        !o.status.success() && err(&o).contains("wrong password"),
        "{}",
        err(&o)
    );

    // --- terminal approval: pairing, then a persistent signing permission.
    let id = Identity::generate();
    let mut sc = SignerClient::connect(&id, {
        let mut o = ConnectOptions::new("Terminal Test App");
        o.endpoint = Some(env.signer.clone());
        o.read_timeout = Some(std::time::Duration::from_secs(60));
        o
    })
    .unwrap();
    let t = std::thread::spawn(move || {
        let pk = sc.get_public_key(None);
        (sc, pk)
    });
    let o = ctl(&env, &["watch", "--max", "1"], &format!("{PW}\na\n"));
    let text = out(&o);
    assert!(o.status.success(), "{text}\n{}", err(&o));
    assert!(
        text.contains("Terminal Test App") && text.contains("UNVERIFIED") && text.contains("PAIR"),
        "{text}"
    );
    let (mut sc, pk) = t.join().unwrap();
    let pk = pk.unwrap();

    let t = std::thread::spawn(move || {
        let r = sc.sign_event(
            &json!({"kind": 1, "content": "signed from the terminal"}),
            None,
        );
        (sc, r)
    });
    let o = ctl(&env, &["watch", "--max", "1"], &format!("{PW}\np\n"));
    let text = out(&o);
    assert!(
        o.status.success()
            && text.contains("signed from the terminal")
            && text.contains("sign_event"),
        "{text}\n{}",
        err(&o)
    );
    let (mut sc, ev) = t.join().unwrap();
    let ev = ev.unwrap();
    ev.verify().unwrap();
    assert_eq!(ev.pubkey.to_hex(), pk);
    sc.sign_event(&json!({"kind": 1, "content": "no prompt now"}), None)
        .unwrap();

    let o = ctl(&env, &["grants"], &format!("{PW}\n"));
    assert!(
        out(&o).contains("Allow") && out(&o).contains("sign_event"),
        "{}",
        out(&o)
    );
    let o = ctl(&env, &["clients"], &format!("{PW}\n"));
    assert!(
        out(&o).contains("Terminal Test App") && out(&o).contains("unverified"),
        "{}",
        out(&o)
    );
    let o = ctl(&env, &["log", "5"], &format!("{PW}\n"));
    assert!(
        out(&o).contains("allowed_by_user") && !out(&o).contains("signed from the terminal"),
        "no content in the log: {}",
        out(&o)
    );

    // Locking and status.
    assert!(ctl(&env, &["lock"], &format!("{PW}\n")).status.success());
    assert!(out(&ctl(&env, &["status"], "")).contains("Locked"));
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_remote_signing_is_opt_in_and_creates_bunker_uris() {
    let (env, cfg) = env();
    let daemon = embrd::start(cfg).await.unwrap();
    let relay = embr_nip46::testing::TestRelay::start(Default::default()).await;
    let pw = format!("{PW}\n");
    assert!(ctl(&env, &["init"], &pw).status.success());
    assert!(
        ctl(&env, &["accounts", "add", "main"], &pw)
            .status
            .success()
    );

    // Off by default; nothing touches the network.
    let o = ctl(&env, &["remote", "status"], &pw);
    assert!(
        out(&o).contains("off (default)") && out(&o).contains("not running"),
        "{}",
        out(&o)
    );
    // Cannot enable without relays, and relays are validated.
    let o = ctl(&env, &["remote", "enable"], &pw);
    assert!(
        !o.status.success() && err(&o).contains("relay"),
        "{}",
        err(&o)
    );
    assert!(
        !ctl(&env, &["remote", "relays", "add", "ws://evil.example"], &pw)
            .status
            .success()
    );
    assert!(
        !ctl(&env, &["remote", "bunker", "main"], &pw)
            .status
            .success(),
        "no bunker while off"
    );
    assert_eq!(relay.total_connections(), 0);

    assert!(
        ctl(&env, &["remote", "relays", "add", &relay.url()], &pw)
            .status
            .success()
    );
    assert!(ctl(&env, &["remote", "enable"], &pw).status.success());
    let o = ctl(&env, &["remote", "bunker", "main", "--qr"], &pw);
    let text = out(&o);
    assert!(o.status.success(), "{}", err(&o));
    let uri = text
        .lines()
        .find(|l| l.starts_with("bunker://"))
        .unwrap_or_default();
    let parsed = embr_nip46::uri::BunkerUri::parse(uri).unwrap();
    assert_eq!(parsed.relays.len(), 1);
    assert!(parsed.secret.is_some());
    assert!(
        text.contains('\u{2588}') || text.contains('\u{2580}') || text.contains('\u{2584}'),
        "a QR code is printed"
    );
    for _ in 0..100 {
        if relay.connections() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(relay.connections(), 1);
    let o = ctl(&env, &["remote", "status"], &pw);
    assert!(
        out(&o).contains("ON")
            && out(&o).contains("connected")
            && out(&o).contains("transport key"),
        "{}",
        out(&o)
    );

    assert!(ctl(&env, &["remote", "disable"], &pw).status.success());
    for _ in 0..100 {
        if relay.connections() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(relay.connections(), 0);
    daemon.shutdown().await;
}
