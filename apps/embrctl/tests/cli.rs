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
