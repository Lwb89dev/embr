//! Start-up, accept loops, idle auto-lock and shutdown.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use embr_ipc::control::VaultState;
use embr_platform::instance::InstanceLock;
use embr_platform::paths;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

use crate::state::{DaemonConfig, Shared};
use crate::{client_api, control_api, log};

/// Start-up failures.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Another daemon of this user is running.
    #[error("another embrd instance is already running for this user")]
    AlreadyRunning,
    /// File-system or socket problem.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// A running daemon.
pub struct DaemonHandle {
    /// Shared state (tests and embedders can inspect it).
    pub shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
    _lock: InstanceLock,
}

fn bind(path: &Path) -> Result<UnixListener, DaemonError> {
    paths::check_socket_path(path)?;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        paths::ensure_private_dir(dir)?;
    }
    // We hold the instance lock, so an existing socket file is stale (left by a crash).
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

/// Starts the daemon: hardening, instance lock, sockets, background tasks.
pub async fn start(cfg: DaemonConfig) -> Result<DaemonHandle, DaemonError> {
    if cfg.harden {
        // (The binary hardens before creating threads and sets this to false; embedders that call
        // `start` directly get best-effort hardening here, without the per-thread guarantee.)
        let report = embr_platform::harden::harden_process();
        for m in &report.applied {
            log(&format!("hardening: {m}"));
        }
        for (m, why) in &report.failed {
            log(&format!("hardening FAILED: {m}: {why}"));
        }
    }
    paths::ensure_private_dir(&cfg.runtime_dir)?;
    paths::ensure_private_dir(&cfg.data_dir)?;
    let lock = InstanceLock::acquire(&cfg.runtime_dir.join("embrd.lock"))?
        .ok_or(DaemonError::AlreadyRunning)?;

    let signer = bind(&cfg.signer_socket)?;
    let control = bind(&cfg.control_socket)?;
    let shared = Shared::new(cfg);

    let tasks = vec![
        tokio::spawn(accept_loop(signer, shared.clone(), false)),
        tokio::spawn(accept_loop(control, shared.clone(), true)),
        tokio::spawn(idle_lock_task(shared.clone())),
    ];
    log(&format!(
        "listening on {}",
        shared.cfg.signer_socket.display()
    ));
    Ok(DaemonHandle {
        shared,
        tasks,
        _lock: lock,
    })
}

impl DaemonHandle {
    /// Stops accepting, locks the vault (wiping keys), closes connections and removes the sockets.
    pub async fn shutdown(self) {
        self.shared.shutdown.cancel();
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
        }
        self.shared.lock_now("shutdown");
        let _ = std::fs::remove_file(&self.shared.cfg.signer_socket);
        let _ = std::fs::remove_file(&self.shared.cfg.control_socket);
        log("stopped");
    }

    /// Resolves when shutdown was requested elsewhere.
    pub async fn stopped(&self) {
        self.shared.shutdown.cancelled().await;
    }
}

async fn accept_loop(listener: UnixListener, shared: Arc<Shared>, control: bool) {
    loop {
        tokio::select! {
            _ = shared.shutdown.cancelled() => return,
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    let sh = shared.clone();
                    if control {
                        tokio::spawn(control_api::serve(sh, stream));
                    } else {
                        tokio::spawn(client_api::serve(sh, stream));
                    }
                }
                Err(e) => {
                    log(&format!("accept failed: {e}"));
                    tokio::time::sleep(Duration::from_millis(100)).await; // e.g. EMFILE: do not spin
                }
            },
        }
    }
}

/// Locks the vault after the configured idle time. Event-driven: it sleeps until the deadline and
/// is woken only when the deadline can have changed (no polling).
async fn idle_lock_task(shared: Arc<Shared>) {
    loop {
        let deadline = {
            let g = shared.lock();
            (g.vault_state() == VaultState::Unlocked && g.settings.lock_timeout_secs > 0)
                .then(|| g.last_activity + Duration::from_secs(g.settings.lock_timeout_secs))
        };
        tokio::select! {
            _ = shared.shutdown.cancelled() => return,
            _ = shared.activity.notified() => {}
            () = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let expired = {
                    let g = shared.lock();
                    g.vault_state() == VaultState::Unlocked
                        && g.settings.lock_timeout_secs > 0
                        && g.last_activity.elapsed() >= Duration::from_secs(g.settings.lock_timeout_secs)
                };
                if expired {
                    shared.lock_now("idle timeout");
                }
            }
        }
    }
}
