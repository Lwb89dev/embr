//! `embr --tray`: a small resident helper that puts an icon in the system tray, shows how many requests are
//! waiting, and raises a desktop notification when a new one arrives while the window is closed.
//!
//! It holds **no key, no password and no control token**: it only calls the daemon's unauthenticated
//! `status`, which says whether the vault is unlocked and how many requests are pending — never who asks or
//! what for. Clicking the icon starts the normal window (`embr`), which asks for the password as usual.
//! Linux only (StatusNotifierItem); other platforms report that plainly instead of pretending.

// Only Linux runs the tray; the portable logic below is still compiled (and unit-tested) everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

use embr_ipc::control::VaultState;

/// What the tray knows about the daemon.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// The daemon answered the last poll.
    pub daemon_up: bool,
    /// Vault state, if the daemon is up.
    pub vault: Option<VaultState>,
    /// Requests waiting for a decision.
    pub pending: usize,
}

/// Tooltip title and body.
pub fn tooltip(o: &Observed) -> (String, String) {
    let body = match (o.daemon_up, o.vault, o.pending) {
        (false, _, _) => "The signer daemon is not running.".to_owned(),
        (true, Some(VaultState::Missing), _) => "No vault yet: open Embr to create one.".to_owned(),
        (true, Some(VaultState::Locked), _) => "Locked.".to_owned(),
        (true, _, 0) => "Unlocked. Nothing is waiting.".to_owned(),
        (true, _, 1) => "1 request is waiting for your decision.".to_owned(),
        (true, _, n) => format!("{n} requests are waiting for your decision."),
    };
    ("Embr".to_owned(), body)
}

/// The icon should ask for attention.
pub fn needs_attention(o: &Observed) -> bool {
    o.daemon_up && o.pending > 0
}

/// A notification is due when more requests wait than at the previous poll.
pub fn should_notify(prev: &Observed, now: &Observed) -> bool {
    now.daemon_up && now.pending > prev.pending
}

/// Notification text. Counts only: the tray cannot know (and never shows) who asks or what for.
pub fn notification_body(pending: usize) -> String {
    if pending == 1 {
        "1 request is waiting for your approval.".to_owned()
    } else {
        format!("{pending} requests are waiting for your approval.")
    }
}

/// Polls the daemon once, reconnecting if needed.
pub fn poll(
    client: &mut Option<embr_client::control::ControlClient>,
    endpoint: &Option<PathBuf>,
) -> Observed {
    if client.is_none()
        && let Ok(c) = embr_client::control::ControlClient::connect(endpoint.clone())
    {
        // A daemon that stops answering must not freeze the tray. (Windows named pipes opened as files have no
        // read timeout; the tray does not run there, so only the portable polling code is compiled.)
        #[cfg(unix)]
        let c = {
            let mut c = c;
            let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
            c
        };
        *client = Some(c);
    }
    let Some(c) = client.as_mut() else {
        return Observed::default();
    };
    match c.status() {
        Ok(s) => Observed {
            daemon_up: true,
            vault: Some(s.vault),
            pending: s.pending,
        },
        Err(_) => {
            *client = None;
            Observed::default()
        }
    }
}

/// Path of a lock file in the per-user runtime directory, which is created private if missing.
pub fn lock_path(name: &str) -> Option<PathBuf> {
    let dir = embr_platform::paths::runtime_dir();
    embr_platform::paths::ensure_private_dir(&dir).ok()?;
    Some(dir.join(name))
}

/// Is a window of the app already open? (It holds `embr-gui.lock`.)
pub fn gui_running() -> bool {
    lock_path("embr-gui.lock")
        .and_then(|p| embr_platform::instance::InstanceLock::acquire(&p).ok())
        .is_some_and(|l| l.is_none())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Observed, needs_attention, should_notify, tooltip};
    use ksni::blocking::TrayMethods;
    use std::path::PathBuf;
    use std::time::Duration;

    /// 64 px icon as ARGB32 (network byte order), as the StatusNotifierItem spec wants it.
    fn icon() -> Option<ksni::Icon> {
        let img =
            eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-64.png")).ok()?;
        let mut data = img.rgba;
        for px in data.as_chunks_mut::<4>().0 {
            px.rotate_right(1); // RGBA -> ARGB
        }
        Some(ksni::Icon {
            width: i32::try_from(img.width).ok()?,
            height: i32::try_from(img.height).ok()?,
            data,
        })
    }

    /// Starts the normal window. A second window is refused by the window's own single-instance lock.
    fn open_window() {
        if let Ok(exe) = std::env::current_exe() {
            let _ = std::process::Command::new(exe)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    }

    struct EmbrTray {
        obs: Observed,
        icon: Option<ksni::Icon>,
    }

    impl ksni::Tray for EmbrTray {
        fn id(&self) -> String {
            "embr".into()
        }
        fn title(&self) -> String {
            "Embr".into()
        }
        fn category(&self) -> ksni::Category {
            ksni::Category::ApplicationStatus
        }
        fn status(&self) -> ksni::Status {
            if needs_attention(&self.obs) {
                ksni::Status::NeedsAttention
            } else {
                ksni::Status::Active
            }
        }
        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            self.icon.iter().cloned().collect()
        }
        fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
            self.icon.iter().cloned().collect()
        }
        fn tool_tip(&self) -> ksni::ToolTip {
            let (title, description) = tooltip(&self.obs);
            ksni::ToolTip {
                title,
                description,
                icon_name: String::new(),
                icon_pixmap: Vec::new(),
            }
        }
        fn activate(&mut self, _x: i32, _y: i32) {
            open_window();
        }
        fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
            use ksni::menu::StandardItem;
            vec![
                StandardItem {
                    label: "Open Embr".into(),
                    activate: Box::new(|_| open_window()),
                    ..Default::default()
                }
                .into(),
                StandardItem {
                    label: tooltip(&self.obs).1,
                    enabled: false,
                    ..Default::default()
                }
                .into(),
                ksni::MenuItem::Separator,
                StandardItem {
                    label: "Quit the tray".into(),
                    icon_name: "application-exit".into(),
                    activate: Box::new(|_| std::process::exit(0)),
                    ..Default::default()
                }
                .into(),
            ]
        }
    }

    pub fn run(endpoint: Option<PathBuf>) -> i32 {
        // One tray per user.
        let _lock = match super::lock_path("embr-tray.lock")
            .map(|p| embr_platform::instance::InstanceLock::acquire(&p))
        {
            Some(Ok(Some(l))) => Some(l),
            Some(Ok(None)) => {
                eprintln!("embr: the tray is already running");
                return 0;
            }
            _ => None, // cannot lock: carry on rather than refuse to start
        };
        let tray = EmbrTray {
            obs: Observed::default(),
            icon: icon(),
        };
        let handle = match tray.spawn() {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "embr: cannot show a tray icon: {e}\n(a StatusNotifier host is needed: KDE, Waybar's tray module, quickshell, or GNOME's AppIndicator extension)"
                );
                return 1;
            }
        };
        let mut client = None;
        let mut prev = Observed::default();
        loop {
            let now = super::poll(&mut client, &endpoint);
            if now != prev {
                let copy = now.clone();
                let _ = handle.update(move |t| t.obs = copy);
            }
            // While the window is open it announces requests itself; two notifications would be noise.
            if should_notify(&prev, &now) && !super::gui_running() {
                crate::notify::pending_waiting(now.pending);
            }
            prev = now;
            if handle.is_closed() {
                eprintln!("embr: lost the tray host; exiting");
                return 1;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    }
}

/// Runs the tray until it is quit. Returns the process exit code.
#[cfg(target_os = "linux")]
pub fn run(endpoint: Option<PathBuf>) -> i32 {
    linux::run(endpoint)
}

/// Runs the tray until it is quit. Returns the process exit code.
#[cfg(not(target_os = "linux"))]
pub fn run(_endpoint: Option<PathBuf>) -> i32 {
    eprintln!(
        "embr: the tray icon is only implemented on Linux (StatusNotifierItem); not available here"
    );
    2
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn up(vault: VaultState, pending: usize) -> Observed {
        Observed {
            daemon_up: true,
            vault: Some(vault),
            pending,
        }
    }

    #[test]
    fn the_tooltip_says_what_matters_and_never_names_an_app() {
        assert!(tooltip(&Observed::default()).1.contains("not running"));
        assert!(tooltip(&up(VaultState::Missing, 0)).1.contains("No vault"));
        assert_eq!(tooltip(&up(VaultState::Locked, 0)).1, "Locked.");
        assert!(tooltip(&up(VaultState::Unlocked, 0)).1.contains("Nothing"));
        assert!(
            tooltip(&up(VaultState::Unlocked, 1))
                .1
                .starts_with("1 request is")
        );
        assert!(
            tooltip(&up(VaultState::Unlocked, 3))
                .1
                .starts_with("3 requests are")
        );
    }

    #[test]
    fn only_a_rise_in_pending_requests_notifies() {
        let none = up(VaultState::Unlocked, 0);
        let one = up(VaultState::Unlocked, 1);
        let two = up(VaultState::Unlocked, 2);
        assert!(should_notify(&none, &one));
        assert!(should_notify(&one, &two));
        assert!(!should_notify(&one, &one), "no repeat for the same request");
        assert!(!should_notify(&two, &one), "answering one is not news");
        assert!(
            !should_notify(&one, &Observed::default()),
            "a dead daemon is not a request"
        );
        // A daemon that restarts with requests waiting counts as new ones: the user has not seen them.
        assert!(should_notify(&Observed::default(), &one));
    }

    #[test]
    fn attention_means_a_live_daemon_with_waiting_requests() {
        assert!(needs_attention(&up(VaultState::Unlocked, 1)));
        assert!(!needs_attention(&up(VaultState::Unlocked, 0)));
        assert!(!needs_attention(&Observed {
            daemon_up: false,
            vault: None,
            pending: 4
        }));
    }

    #[test]
    fn the_notification_carries_a_count_only() {
        assert_eq!(
            notification_body(1),
            "1 request is waiting for your approval."
        );
        assert_eq!(
            notification_body(5),
            "5 requests are waiting for your approval."
        );
    }

    /// The tray against a **real daemon**, without ever authenticating: it must see the vault state and the
    /// number of waiting requests, and survive the daemon coming and going.
    #[cfg(unix)]
    #[test]
    fn polling_a_real_daemon_sees_the_vault_state_and_waiting_requests_without_a_password() {
        use embr_client::{ConnectOptions, SignerClient};
        use embr_crypto::Identity;

        let tmp = tempfile::Builder::new().prefix("y").tempdir().unwrap();
        let mut cfg = embrd::DaemonConfig::from_environment();
        cfg.data_dir = tmp.path().join("d");
        cfg.runtime_dir = tmp.path().join("r");
        cfg.signer_socket = cfg.runtime_dir.join("signer.sock");
        cfg.control_socket = cfg.runtime_dir.join("control.sock");
        cfg.kdf = embr_vault::KdfParams::MINIMUM;
        cfg.harden = false;
        let (control, signer) = (cfg.control_socket.clone(), cfg.signer_socket.clone());
        let endpoint = Some(control.clone());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let mut client = None;
        assert_eq!(
            poll(&mut client, &endpoint),
            Observed::default(),
            "no daemon yet"
        );

        let daemon = rt.block_on(embrd::start(cfg)).unwrap();
        let o = poll(&mut client, &endpoint);
        assert_eq!(
            (o.daemon_up, o.vault, o.pending),
            (true, Some(VaultState::Missing), 0)
        );

        let mut ctl = embr_client::control::ControlClient::connect(Some(control)).unwrap();
        ctl.create_vault("correct horse battery staple").unwrap();
        let acct = ctl
            .call("add_generated", serde_json::json!({"label": "main"}))
            .unwrap();
        assert!(acct.get("id").is_some());
        let o = poll(&mut client, &endpoint);
        assert_eq!((o.vault, o.pending), (Some(VaultState::Unlocked), 0));

        // An app asks to pair: the tray sees one waiting request (a count, nothing else).
        let app = std::thread::spawn(move || {
            let mut opts = ConnectOptions::new("Tray Test App");
            opts.endpoint = Some(signer);
            opts.read_timeout = Some(Duration::from_secs(20));
            let mut c = SignerClient::connect(&Identity::generate(), opts).unwrap();
            let _ = c.get_public_key(None); // blocks until answered or refused
        });
        let start = std::time::Instant::now();
        let seen = loop {
            let o = poll(&mut client, &endpoint);
            if o.pending == 1 {
                break o;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "never saw the request: {o:?}"
            );
            std::thread::sleep(Duration::from_millis(30));
        };
        assert!(needs_attention(&seen) && should_notify(&Observed::default(), &seen));

        // The daemon going away is an observation, not an error, and recovery is automatic.
        rt.block_on(daemon.shutdown());
        let _ = app.join();
        assert_eq!(poll(&mut client, &endpoint), Observed::default());
        assert!(
            client.is_none(),
            "the dead connection is dropped so the next poll reconnects"
        );
    }
}
