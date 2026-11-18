//! The NIP-46 signer service: relay events in, JSON-RPC calls to a [`Handler`], responses out.
//!
//! All **protocol-level** defences live here and run *before* a call reaches the handler (and
//! before any decryption where possible):
//!
//! 1. kind 24133, exactly one `p` tag naming one of our transport keys, valid id and signature;
//! 2. freshness: `created_at` within ±10 minutes of our clock (relays can replay old events);
//! 3. replay: every event id is processed at most once (bounded cache);
//! 4. per-client rate limit (token bucket) **before** the ECDH/decryption work;
//! 5. strict JSON-RPC parsing.
//!
//! Authorisation (is this client paired? may it sign kind 1?) is the handler's business — in the
//! daemon it is the same policy engine that serves local clients.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use embr_core::Pubkey32;
use embr_crypto::{Event, EventTemplate, Identity, Limits};
use embr_policy::RateLimiter;
use serde_json::json;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::protocol::{self, RpcResponse};
use crate::relay::{AuthSigner, Incoming, Pool, RelayStatus};

/// A decoded, protocol-valid request handed to the [`Handler`].
#[derive(Clone, Debug)]
pub struct Call {
    /// Transport key the request was addressed to (selects the account).
    pub signer: Pubkey32,
    /// The client (author of the request event).
    pub client: Pubkey32,
    /// JSON-RPC id.
    pub id: String,
    /// Method.
    pub method: String,
    /// String parameters.
    pub params: Vec<String>,
    /// Relay the request arrived on.
    pub relay: String,
}

/// The future a handler returns: `Ok(result)` or `Err(error text)`.
pub type CallFuture = Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;

/// Implemented by the daemon.
pub trait Handler: Send + Sync + 'static {
    /// Handles one call. May take as long as a human takes to approve; the service imposes no
    /// timeout of its own (the handler's request timeout does).
    fn call(&self, call: Call) -> CallFuture;
}

/// Tunables.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Token-bucket burst per client.
    pub rate_burst: u32,
    /// Sustained requests per second per client.
    pub rate_per_sec: u32,
    /// Maximum calls being handled at once.
    pub max_inflight: usize,
    /// Accepted clock difference for `created_at`, in seconds.
    pub freshness_secs: u64,
    /// How many processed event ids to remember.
    pub seen_cache: usize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            rate_burst: 10,
            rate_per_sec: 2,
            max_inflight: 64,
            freshness_secs: 600,
            seen_cache: 8192,
        }
    }
}

/// Counters, mainly for tests and diagnostics (no event content, no keys).
#[derive(Debug, Default)]
pub struct Stats {
    /// Events accepted for processing.
    pub accepted: AtomicU64,
    /// Dropped: not NIP-46 for us / bad signature.
    pub dropped_invalid: AtomicU64,
    /// Dropped: stale or future `created_at`.
    pub dropped_stale: AtomicU64,
    /// Dropped: event id seen before (replay).
    pub dropped_replay: AtomicU64,
    /// Dropped: client rate limited.
    pub dropped_rate: AtomicU64,
    /// Dropped: could not decrypt / malformed JSON-RPC.
    pub dropped_undecodable: AtomicU64,
    /// Dropped: too many calls in flight.
    pub dropped_busy: AtomicU64,
}

type Signers = Arc<RwLock<HashMap<Pubkey32, Arc<Identity>>>>;

struct AuthFromSigners(Signers);

impl AuthSigner for AuthFromSigners {
    fn sign_auth(&self, relay_url: &str, challenge: &str) -> Option<Event> {
        let g = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let id = g.values().next()?; // any transport key; never a user key
        let tpl = EventTemplate {
            kind: 22242,
            content: String::new(),
            tags: vec![
                vec!["relay".into(), relay_url.to_owned()],
                vec!["challenge".into(), challenge.to_owned()],
            ],
            created_at: Some(now()),
            pubkey: None,
            id: None,
        };
        id.sign_event(&tpl, &Limits::default()).ok()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A running service.
pub struct Service {
    signers: Signers,
    pool: Arc<Pool>,
    /// Counters.
    pub stats: Arc<Stats>,
    cancel: CancellationToken,
}

impl Service {
    /// Starts the service. No relay is contacted until [`Service::set_relays`] is called.
    pub fn start(
        handler: Arc<dyn Handler>,
        cfg: ServiceConfig,
        parent: &CancellationToken,
    ) -> Arc<Service> {
        Self::start_with(handler, cfg, parent, None)
    }

    /// Like [`Service::start`], but `wss://` relays are verified against `roots` instead of the bundled
    /// Mozilla roots. Test-only (the `testing` feature is never enabled in the shipped programs).
    #[cfg(feature = "testing")]
    pub fn start_trusting(
        handler: Arc<dyn Handler>,
        cfg: ServiceConfig,
        parent: &CancellationToken,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Arc<Service>, String> {
        Ok(Self::start_with(
            handler,
            cfg,
            parent,
            Some(crate::relay::trusting_config(roots)?),
        ))
    }

    fn start_with(
        handler: Arc<dyn Handler>,
        cfg: ServiceConfig,
        parent: &CancellationToken,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Arc<Service> {
        let cancel = parent.child_token();
        let signers: Signers = Arc::default();
        let (pool, rx) = Pool::with_tls(
            Arc::new(AuthFromSigners(signers.clone())),
            cancel.clone(),
            tls,
        );
        let svc = Arc::new(Service {
            signers: signers.clone(),
            pool: pool.clone(),
            stats: Arc::default(),
            cancel: cancel.clone(),
        });
        tokio::spawn(run(
            rx,
            signers,
            pool,
            handler,
            cfg,
            svc.stats.clone(),
            cancel,
        ));
        svc
    }

    /// Adds (or replaces) a transport key and starts listening for requests addressed to it.
    pub fn add_signer(&self, id: Identity) {
        let pk: Result<Pubkey32, _> = id.pubkey_hex().parse();
        if let Ok(pk) = pk {
            let mut g = self.signers.write().unwrap_or_else(PoisonError::into_inner);
            g.insert(pk, Arc::new(id));
            self.pool
                .set_pubkeys(g.keys().map(ToString::to_string).collect());
        }
    }

    /// Stops listening for a transport key.
    pub fn remove_signer(&self, pk: &Pubkey32) {
        let mut g = self.signers.write().unwrap_or_else(PoisonError::into_inner);
        g.remove(pk);
        self.pool
            .set_pubkeys(g.keys().map(ToString::to_string).collect());
    }

    /// Stops listening for *new* requests (all transport keys) while letting calls already in
    /// flight finish and publish their responses. Follow with [`Service::stop`] after a drain delay.
    pub fn clear_signers(&self) {
        self.signers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.pool.set_pubkeys(Vec::new());
    }

    /// Replaces the relay set.
    pub fn set_relays(&self, urls: &[String]) {
        self.pool.set_relays(urls);
    }

    /// Relay states.
    pub fn status(&self) -> Vec<RelayStatus> {
        self.pool.status()
    }

    /// Sends an unsolicited signer→client message (e.g. the `connect` response of a
    /// `nostrconnect://` flow) from transport key `signer` to `client`. Returns relays that accepted it.
    pub async fn send(&self, signer: &Pubkey32, client: &Pubkey32, payload: &str) -> usize {
        let id = self
            .signers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(signer)
            .cloned();
        let Some(id) = id else { return 0 };
        let Ok(client_pk) = embr_crypto::parse_public_key(&client.to_string()) else {
            return 0;
        };
        match protocol::seal(&id, &client_pk, payload, now(), &Limits::default()) {
            Ok(ev) => self.pool.publish(&ev).await,
            Err(_) => 0,
        }
    }

    /// Disconnects from all relays and stops the service.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

struct Seen {
    set: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl Seen {
    /// `true` if `id` was already seen (and records it otherwise).
    fn check_and_insert(&mut self, id: String) -> bool {
        if self.set.contains(&id) {
            return true;
        }
        self.set.insert(id.clone());
        self.order.push_back(id);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        false
    }
}

async fn run(
    mut rx: mpsc::Receiver<Incoming>,
    signers: Signers,
    pool: Arc<Pool>,
    handler: Arc<dyn Handler>,
    cfg: ServiceConfig,
    stats: Arc<Stats>,
    cancel: CancellationToken,
) {
    let limits = Limits::default();
    let seen = Mutex::new(Seen {
        set: HashSet::new(),
        order: VecDeque::new(),
        cap: cfg.seen_cache,
    });
    let mut limiter: RateLimiter<Pubkey32> = RateLimiter::new(cfg.rate_burst, cfg.rate_per_sec);
    let started = std::time::Instant::now();
    let inflight = Arc::new(Semaphore::new(cfg.max_inflight));
    loop {
        let inc = tokio::select! {
            () = cancel.cancelled() => { pool.shutdown(); return; }
            inc = rx.recv() => match inc { Some(i) => i, None => return },
        };
        let ev = &inc.event;
        let drop_with = |c: &AtomicU64| {
            c.fetch_add(1, Ordering::Relaxed);
        };

        // 1. addressed to one of our transport keys, right kind, valid id + signature.
        let signer = protocol::addressed_to(ev)
            .and_then(|hex| hex.parse::<Pubkey32>().ok())
            .and_then(|pk| {
                signers
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&pk)
                    .cloned()
            });
        let Some(signer) = signer else {
            drop_with(&stats.dropped_invalid);
            continue;
        };
        if ev.kind.as_u16() != protocol::KIND || ev.verify().is_err() {
            drop_with(&stats.dropped_invalid);
            continue;
        }
        // 2. freshness.
        if ev.created_at.as_secs().abs_diff(now()) > cfg.freshness_secs {
            drop_with(&stats.dropped_stale);
            continue;
        }
        // 3. replay.
        if seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check_and_insert(ev.id.to_hex())
        {
            drop_with(&stats.dropped_replay);
            continue;
        }
        // 4. rate limit per client, before decrypting.
        let Ok(client) = ev.pubkey.to_hex().parse::<Pubkey32>() else {
            drop_with(&stats.dropped_invalid);
            continue;
        };
        let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if limiter.check(&client, now_ms).is_err() {
            drop_with(&stats.dropped_rate);
            continue;
        }
        // 5. decrypt + strict parse.
        let Ok((client_pk, req)) = protocol::open_request(&signer, ev, &limits) else {
            drop_with(&stats.dropped_undecodable);
            continue;
        };
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            drop_with(&stats.dropped_busy);
            continue;
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);

        let call = Call {
            signer: signer.pubkey_hex().parse().unwrap_or(client),
            client,
            id: req.id.clone(),
            method: req.method,
            params: req.params,
            relay: inc.relay,
        };
        let (handler, pool, limits) = (handler.clone(), pool.clone(), limits.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let result = handler.call(call).await;
            let resp = match result {
                Ok(r) => RpcResponse {
                    id: req.id,
                    result: Some(r),
                    error: None,
                },
                Err(e) => RpcResponse {
                    id: req.id,
                    result: None,
                    error: Some(e),
                },
            };
            if let Ok(payload) = serde_json::to_string(&json!(resp)) {
                if let Ok(ev) = protocol::seal(&signer, &client_pk, &payload, now(), &limits) {
                    pool.publish(&ev).await;
                }
            }
        });
    }
}
