//! Test harness: a real daemon on real sockets, a real SDK client, a real control client.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use embr_client::control::ControlClient;
use embr_client::{ClientError, ConnectOptions, SignerClient};
use embr_core::AccountMeta;
use embr_crypto::Identity;
use embr_ipc::control::{DecisionWire, PendingView, ScopeWire};
use embr_vault::KdfParams;
use embrd::{DaemonConfig, DaemonHandle};
use serde_json::{Value, json};

pub const PW: &str = "correct horse battery staple";

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub run: PathBuf,
    pub data: PathBuf,
}

impl Env {
    pub fn new() -> Self {
        let tmp = tempfile::Builder::new().prefix("e").tempdir().unwrap();
        let run = tmp.path().join("r");
        let data = tmp.path().join("d");
        Env { tmp, run, data }
    }
    pub fn signer(&self) -> PathBuf {
        self.run.join("signer.sock")
    }
    pub fn control(&self) -> PathBuf {
        self.run.join("control.sock")
    }
    pub fn config(&self) -> DaemonConfig {
        let mut cfg = DaemonConfig::from_environment();
        cfg.data_dir = self.data.clone();
        cfg.runtime_dir = self.run.clone();
        cfg.signer_socket = self.signer();
        cfg.control_socket = self.control();
        cfg.kdf = KdfParams::MINIMUM; // fast but legal
        cfg.harden = false; // do not harden the test process
        cfg
    }
}

pub async fn boot(env: &Env) -> DaemonHandle {
    embrd::start(env.config()).await.unwrap()
}

pub async fn boot_with(env: &Env, f: impl FnOnce(&mut DaemonConfig)) -> DaemonHandle {
    let mut cfg = env.config();
    f(&mut cfg);
    embrd::start(cfg).await.unwrap()
}

pub fn ctl(env: &Env) -> ControlClient {
    let mut c = ControlClient::connect(Some(env.control())).unwrap();
    // No default timeout exists; without one a daemon that never answers hangs the whole test run
    // (a macOS CI job sat in `cargo test` for hours). A timeout turns that into a named failure.
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    c
}

/// A control client with a freshly created vault and `n` accounts.
pub fn vault_with_accounts(env: &Env, n: usize) -> (ControlClient, Vec<AccountMeta>) {
    let mut c = ctl(env);
    c.create_vault(PW).unwrap();
    let accounts = (0..n)
        .map(|i| {
            let v = c
                .call("add_generated", json!({"label": format!("acct{i}")}))
                .unwrap();
            serde_json::from_value(v).unwrap()
        })
        .collect();
    (c, accounts)
}

pub fn opts(env: &Env, name: &str) -> ConnectOptions {
    let mut o = ConnectOptions::new(name);
    o.endpoint = Some(env.signer());
    o.read_timeout = Some(Duration::from_secs(20));
    o
}

pub fn client(env: &Env, name: &str) -> (Identity, SignerClient) {
    let id = Identity::generate();
    let c = SignerClient::connect(&id, opts(env, name)).unwrap();
    (id, c)
}

pub fn spawn<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> JoinHandle<R> {
    std::thread::spawn(f)
}

/// Polls the control channel until at least `n` requests are pending.
pub fn wait_pending(c: &mut ControlClient, n: usize) -> Vec<PendingView> {
    let start = Instant::now();
    loop {
        let p = c.pending().unwrap();
        if p.len() >= n {
            return p;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {n} pending request(s), have {}",
            p.len()
        );
        std::thread::sleep(Duration::from_millis(15));
    }
}

pub fn wait_no_pending(c: &mut ControlClient) {
    let start = Instant::now();
    while !c.pending().unwrap().is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "pending requests never went away"
        );
        std::thread::sleep(Duration::from_millis(15));
    }
}

/// Pairs a fresh client to `account` (the client call happens on a helper thread).
pub fn pair(
    env: &Env,
    c: &mut ControlClient,
    account: &AccountMeta,
    name: &str,
) -> (Identity, SignerClient) {
    let (id, mut sc) = client(env, name);
    let t = spawn(move || {
        let pk = sc.get_public_key(None);
        (sc, pk)
    });
    let v = wait_pending(c, 1).remove(0);
    c.decide(
        &v,
        DecisionWire::Pair {
            account: account.id,
        },
        None,
    )
    .unwrap();
    let (sc, pk) = t.join().unwrap();
    assert_eq!(pk.unwrap(), account.pubkey_hex);
    (id, sc)
}

pub fn exact_kind(kind: u16) -> Option<ScopeWire> {
    Some(ScopeWire {
        kind: embr_policy::KindScope::Exact(kind),
        peer: None,
        uses: None,
    })
}

pub fn code_of<T: std::fmt::Debug>(r: Result<T, ClientError>) -> u16 {
    match r {
        Err(ClientError::Rpc(e)) => e.code,
        other => panic!("expected an RPC error, got {other:?}"),
    }
}

pub fn note(content: &str) -> Value {
    json!({"kind": 1, "content": content})
}

/// A raw protocol connection for malformed-input tests.
pub struct Raw {
    pub reader: BufReader<UnixStream>,
    pub writer: UnixStream,
}

impl Raw {
    pub fn connect(env: &Env) -> Self {
        let s = UnixStream::connect(env.signer()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // A write must not wait forever either: on macOS a Unix socket buffers only a few KiB, so a
        // large write to a peer that has stopped reading blocks (this hung a macOS CI job for hours).
        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        Raw {
            writer: s.try_clone().unwrap(),
            reader: BufReader::new(s),
        }
    }
    pub fn read(&mut self) -> Option<Value> {
        let mut l = String::new();
        match self.reader.read_line(&mut l) {
            Ok(0) => None,
            Ok(_) => Some(serde_json::from_str(&l).unwrap_or_else(|_| panic!("not JSON: {l:?}"))),
            Err(_) => None,
        }
    }
    /// True if the daemon closes this connection within `t` (replies still in flight are drained first).
    /// A read that merely times out is *not* "closed": that is exactly the difference that hid a bug where
    /// the daemon decided to end a connection but never closed the socket.
    pub fn closed_within(&mut self, t: Duration) -> bool {
        let _ = self.reader.get_ref().set_read_timeout(Some(t));
        let start = Instant::now();
        loop {
            let mut l = String::new();
            match self.reader.read_line(&mut l) {
                Ok(0) => return true,
                Ok(_) if start.elapsed() > t => return false,
                Ok(_) => {}
                Err(e) => {
                    return !matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    );
                }
            }
        }
    }
    pub fn write(&mut self, line: &str) {
        let _ = self.writer.write_all(line.as_bytes());
        let _ = self.writer.write_all(b"\n");
        let _ = self.writer.flush();
    }
    pub fn server_hello(&mut self) -> Value {
        self.read().unwrap()
    }
    /// Full valid handshake with `id`.
    pub fn login(&mut self, id: &Identity) -> Value {
        let hello = self.server_hello();
        let nonce = hello["nonce"].as_str().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let proof = embr_ipc::auth::make_proof(id, nonce, now).unwrap();
        self.write(&json!({"hello": {"protocol": 1, "client": {"name": "raw", "pubkey": id.pubkey_hex()}, "proof": proof}}).to_string());
        self.read().unwrap()
    }
}
