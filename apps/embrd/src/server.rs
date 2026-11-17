//! Start-up, accept loops, idle auto-lock and shutdown.

use std::sync::Arc;
use std::time::Duration;

use embr_ipc::control::VaultState;
use embr_platform::instance::InstanceLock;
use embr_platform::paths;
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

#[cfg(unix)]
fn bind(path: &std::path::Path) -> Result<tokio::net::UnixListener, DaemonError> {
    paths::check_socket_path(path)?;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        paths::ensure_private_dir(dir)?;
    }
    // We hold the instance lock, so an existing socket file is stale (left by a crash).
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
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

    #[cfg(unix)]
    let (signer, control) = (bind(&cfg.signer_socket)?, bind(&cfg.control_socket)?);
    #[cfg(windows)]
    let (signer, control, security) = {
        // First instances are created *now* so that a squatted pipe name or a security-descriptor
        // failure stops the daemon from starting, instead of surfacing later.
        let sec = Arc::new(embr_platform::windows::UserOnlySecurity::new()?);
        let name = |p: &std::path::PathBuf| p.to_string_lossy().into_owned();
        let signer = (
            embr_platform::windows::create_pipe_instance(&name(&cfg.signer_socket), true, &sec)?,
            name(&cfg.signer_socket),
        );
        let control = (
            embr_platform::windows::create_pipe_instance(&name(&cfg.control_socket), true, &sec)?,
            name(&cfg.control_socket),
        );
        (signer, control, sec)
    };
    let shared = Shared::new(cfg);

    #[cfg(unix)]
    let tasks = vec![
        tokio::spawn(accept_loop(signer, shared.clone(), false)),
        tokio::spawn(accept_loop(control, shared.clone(), true)),
        tokio::spawn(idle_lock_task(shared.clone())),
    ];
    #[cfg(windows)]
    let tasks = vec![
        tokio::spawn(pipe_accept_loop(
            signer.0,
            signer.1,
            security.clone(),
            shared.clone(),
            false,
        )),
        tokio::spawn(pipe_accept_loop(
            control.0,
            control.1,
            security,
            shared.clone(),
            true,
        )),
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
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.shared.cfg.signer_socket);
            let _ = std::fs::remove_file(&self.shared.cfg.control_socket);
        }
        log("stopped");
    }

    /// Resolves when shutdown was requested elsewhere.
    pub async fn stopped(&self) {
        self.shared.shutdown.cancelled().await;
    }
}

#[cfg(unix)]
async fn accept_loop(listener: tokio::net::UnixListener, shared: Arc<Shared>, control: bool) {
    loop {
        tokio::select! {
            _ = shared.shutdown.cancelled() => return,
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    // Same user only. (Other users cannot reach the 0700 directory anyway; this is the
                    // second lock: SO_PEERCRED / LOCAL_PEERCRED.)
                    let Ok(cred) = stream.peer_cred() else { continue };
                    if cred.uid() != embr_platform::paths::current_uid() {
                        continue;
                    }
                    let sh = shared.clone();
                    if control {
                        tokio::spawn(control_api::serve(sh, stream));
                    } else {
                        let peer = embr_ipc::control::PeerHint {
                            pid: cred.pid(),
                            uid: cred.uid(),
                            exe: cred.pid().and_then(embr_platform::peer::exe_of_pid),
                        };
                        tokio::spawn(client_api::serve(sh, stream, peer));
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

/// Windows: serve a named pipe. The pipe's DACL admits only the daemon's own user, so no per-connection
/// identity check is needed; the client's pid is passed on as an (untrusted) hint.
#[cfg(windows)]
async fn pipe_accept_loop(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    name: String,
    security: Arc<embr_platform::windows::UserOnlySecurity>,
    shared: Arc<Shared>,
    control: bool,
) {
    loop {
        tokio::select! {
            _ = shared.shutdown.cancelled() => return,
            r = server.connect() => {
                if let Err(e) = r {
                    log(&format!("pipe connect failed: {e}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let pid = embr_platform::windows::pipe_client_pid(&server);
                let next = match embr_platform::windows::create_pipe_instance(&name, false, &security) {
                    Ok(n) => n,
                    Err(e) => { log(&format!("cannot create the next pipe instance: {e}")); return; }
                };
                let stream = std::mem::replace(&mut server, next);
                let sh = shared.clone();
                if control {
                    tokio::spawn(control_api::serve(sh, stream));
                } else {
                    let peer = embr_ipc::control::PeerHint { pid: pid.and_then(|p| i32::try_from(p).ok()), uid: 0, exe: None };
                    tokio::spawn(client_api::serve(sh, stream, peer));
                }
            }
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
