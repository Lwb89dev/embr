//! `embr` — the Embr desktop app.
//!
//! A thin client of the daemon's control channel: it shows state, collects decisions and sends them
//! back. It holds **no key material** and keeps nothing between runs except what the daemon stores.
//! If this window is closed the daemon (and every previously authorised request) keeps working.
// On Windows this is a GUI-subsystem program: no console window behind it. (As a consequence `embr --version`
// prints nothing there; use `embrctl --version` / `embrd --version`, which are console programs.)
#![cfg_attr(windows, windows_subsystem = "windows")]
#![allow(clippy::print_stderr, unreachable_pub)]

mod backend;
mod demo;
mod notify;
mod tray;
mod ui;

use std::collections::HashSet;

use backend::{Backend, Snapshot};
use eframe::egui;

struct EmbrApp {
    backend: Backend,
    st: ui::UiState,
    seen: HashSet<u64>,
    first: bool,
}

impl EmbrApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        endpoint: Option<std::path::PathBuf>,
        demo: Option<ui::Screen>,
    ) -> Self {
        cc.egui_ctx.set_theme(egui::ThemePreference::System);
        cc.egui_ctx.style_mut_of(egui::Theme::Dark, |s| {
            s.visuals.selection.bg_fill = egui::Color32::from_rgb(150, 80, 20)
        });
        cc.egui_ctx.style_mut_of(egui::Theme::Light, |s| {
            s.visuals.selection.bg_fill = egui::Color32::from_rgb(255, 200, 150)
        });
        let ctx = cc.egui_ctx.clone();
        let mut st = ui::UiState::default();
        let backend = if let Some(screen) = demo {
            st.screen = screen;
            Backend::demo(demo::snapshot())
        } else {
            Backend::spawn(endpoint, move || ctx.request_repaint())
        };
        Self {
            backend,
            st,
            seen: HashSet::new(),
            first: true,
        }
    }

    /// Desktop notification for *new* requests while the window is not focused. Metadata only.
    fn notify_new(&mut self, ctx: &egui::Context, snap: &Snapshot) {
        let focused = ctx.input(|i| i.viewport().focused.unwrap_or(true));
        let enabled = snap.settings.as_ref().is_none_or(|s| s.notifications);
        for p in &snap.pending {
            if self.seen.insert(p.id) && !self.first && !focused && enabled {
                notify::approval_needed(
                    &p.client.name,
                    p.operation.as_deref(),
                    p.event.as_ref().map(|e| e.kind),
                );
            }
        }
        self.seen
            .retain(|id| snap.pending.iter().any(|p| p.id == *id));
        self.first = false;
    }
}

impl eframe::App for EmbrApp {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        let snap = self.backend.snapshot();
        self.notify_new(&ctx, &snap);
        for cmd in ui::ui(root, &snap, &mut self.st) {
            self.backend.send(cmd);
        }
        if !snap.pending.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_secs(30)); // keep "expires in" roughly current
        }
    }
}

fn main() -> eframe::Result {
    let mut endpoint = None;
    let mut demo: Option<ui::Screen> = None;
    let mut tray_mode = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--control-socket" => endpoint = args.next().map(Into::into),
            "--demo" => {
                demo = Some(match args.next().as_deref() {
                    Some("approvals") => ui::Screen::Approvals,
                    Some("accounts") => ui::Screen::Accounts,
                    Some("apps") => ui::Screen::Apps,
                    Some("remote") => ui::Screen::Remote,
                    Some("settings") => ui::Screen::Settings,
                    Some("activity") => ui::Screen::Activity,
                    _ => ui::Screen::Dashboard,
                });
            }
            "--tray" => tray_mode = true,
            "--version" | "-V" => {
                eprintln!("embr {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => {
                eprintln!(
                    "embr: unknown argument {other:?}\nusage: embr [--control-socket PATH] [--demo [screen]] [--tray]"
                );
                std::process::exit(2);
            }
        }
    }
    if tray_mode {
        // The tray helper has no window and handles no secret: it needs none of the setup below.
        std::process::exit(tray::run(endpoint));
    }
    // This process handles the vault password and imported keys while they are typed, so it gets the
    // same protections as the daemon (no core dumps, not readable through ptrace). It must happen
    // before any thread exists; best effort, failures are only reported.
    for (what, why) in embr_platform::harden::harden_process().failed {
        eprintln!("embr: hardening {what} failed: {why}");
    }
    // One window per user (the tray's "Open Embr" can then never pile windows up). Not applied to --demo or to
    // a custom --control-socket, where several windows are legitimate. If the lock cannot be taken for any
    // other reason the window still opens.
    let _single = if demo.is_none() && endpoint.is_none() {
        match tray::lock_path("embr-gui.lock")
            .map(|p| embr_platform::instance::InstanceLock::acquire(&p))
        {
            Some(Ok(Some(lock))) => Some(lock),
            Some(Ok(None)) => {
                eprintln!("embr: a window is already open");
                return Ok(());
            }
            _ => None,
        }
    } else {
        None
    };
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Embr")
        .with_app_id("embr")
        .with_inner_size([980.0, 680.0])
        .with_min_inner_size([720.0, 480.0]);
    if let Some(icon) = icon {
        viewport = viewport.with_icon(icon);
    }
    eframe::run_native(
        "Embr",
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(move |cc| Ok(Box::new(EmbrApp::new(cc, endpoint, demo)))),
    )
}
