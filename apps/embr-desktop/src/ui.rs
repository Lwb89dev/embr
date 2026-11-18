//! The Embr user interface: a pure function from a daemon [`Snapshot`] and the UI's own state to
//! drawing + [`Cmd`]s. It never touches the network and never sees key material: the daemon sends
//! already-sanitised text, labels are plain strings, and nothing here interprets markup.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Color32, RichText, Stroke};
use embr_core::{AccountId, AccountMeta};
use embr_ipc::control::{DecisionWire, PendingKind, PendingView, ScopeWire, Settings, VaultState};
use embr_policy::KindScope;

use crate::backend::{Cmd, Snapshot};

const EMBER: Color32 = Color32::from_rgb(255, 138, 40);
const OK_GREEN: Color32 = Color32::from_rgb(70, 170, 110);
const WARN: Color32 = Color32::from_rgb(235, 170, 40);
const BAD: Color32 = Color32::from_rgb(225, 80, 70);

/// Screens of the left navigation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Screen {
    /// Overview.
    #[default]
    Dashboard,
    /// Pending requests.
    Approvals,
    /// Identities.
    Accounts,
    /// Paired apps and permissions.
    Apps,
    /// NIP-46.
    Remote,
    /// Settings.
    Settings,
    /// Activity log.
    Activity,
}

/// How long an approval should be remembered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Duration {
    /// This request only.
    #[default]
    Once,
    /// Until the app disconnects.
    Session,
    /// 15 minutes.
    Min15,
    /// 1 hour.
    Hour1,
    /// Until revoked.
    Always,
}

/// Per-request choices the user is making.
#[derive(Clone, Debug, Default)]
pub struct Choice {
    /// How long.
    pub duration: Duration,
    /// For signing: all kinds (except direct messages) instead of just this one.
    pub any_kind: bool,
    /// Pairing: the account to bind.
    pub account: Option<AccountId>,
}

/// State owned by the UI (not by the daemon).
#[derive(Default)]
pub struct UiState {
    /// Current screen.
    pub screen: Screen,
    /// Vault password field (cleared as soon as it is sent).
    pub password: String,
    /// Confirmation field when creating a vault.
    pub password2: String,
    /// New account label.
    pub new_label: String,
    /// Import form.
    pub import_label: String,
    /// Import secret (cleared after sending).
    pub import_secret: String,
    /// Import ncryptsec password (cleared after sending).
    pub import_password: String,
    /// Per-request choices.
    pub choices: HashMap<u64, Choice>,
    /// Account whose removal is awaiting confirmation, with the label typed so far.
    pub confirm_remove: Option<(AccountId, String)>,
    /// Export dialog: account, vault password, export password.
    pub export: Option<(AccountId, String, String)>,
    /// Rename dialog.
    pub rename: Option<(AccountId, String)>,
    /// Backup path.
    pub backup_path: String,
    /// Settings being edited.
    pub settings_draft: Option<Settings>,
    /// Relay being added.
    pub new_relay: String,
    /// Account used to create bunker URIs / import nostrconnect.
    pub remote_account: Option<AccountId>,
    /// `nostrconnect://` URI being pasted.
    pub nostrconnect: String,
    /// Change-password fields.
    pub pw_old: String,
    /// New password.
    pub pw_new: String,
}

impl UiState {
    /// Overwrites everything the user typed that is secret (passwords, `nsec`, export password) and
    /// forgets any open confirmation. Called whenever the vault is not unlocked, so that locking the
    /// signer also empties these fields. (egui's own text-edit history may keep copies until the
    /// process exits; see docs/SECURITY.md.)
    pub fn wipe_secrets(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.password2.zeroize();
        self.import_secret.zeroize();
        self.import_password.zeroize();
        self.pw_old.zeroize();
        self.pw_new.zeroize();
        if let Some((_, a, b)) = &mut self.export {
            a.zeroize();
            b.zeroize();
        }
        self.export = None;
        self.confirm_remove = None;
        self.rename = None;
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Human name of an event kind (for the approval prompt).
pub fn kind_name(kind: u16) -> &'static str {
    match kind {
        0 => "profile metadata",
        1 => "short text note",
        3 => "follow list",
        4 => "encrypted direct message (legacy NIP-04)",
        5 => "deletion request",
        6 => "repost",
        7 => "reaction",
        13 => "seal (private message envelope)",
        14 => "chat message (NIP-17)",
        1059 => "gift wrap (private message envelope)",
        9734 => "zap request",
        10002 => "relay list",
        22242 => "relay authentication",
        24133 => "remote-signing message",
        27235 => "HTTP authentication",
        30023 => "long-form article",
        _ => "event",
    }
}

fn card<R>(ui: &mut egui::Ui, accent: Option<Color32>, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let stroke = Stroke::new(
        1.0,
        accent.unwrap_or_else(|| ui.visuals().widgets.noninteractive.bg_stroke.color),
    );
    egui::Frame::group(ui.style())
        .stroke(stroke)
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A fixed-width card, for rows of tiles (a `card` always fills the row, so it cannot be one of several).
fn tile<R>(ui: &mut egui::Ui, width: f32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            // A frame inside `horizontal*` inherits that row layout; the content must stack.
            ui.vertical(|ui| {
                ui.set_width(width);
                ui.set_min_height(72.0);
                add(ui)
            })
            .inner
        })
        .inner
}

fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.label(
        RichText::new(format!(" {text} "))
            .color(Color32::BLACK)
            .background_color(color)
            .small()
            .strong(),
    );
}

fn short(s: &str) -> String {
    let n = s.chars().count();
    if n <= 18 {
        s.to_owned()
    } else {
        format!(
            "{}…{}",
            s.chars().take(10).collect::<String>(),
            s.chars().skip(n - 6).collect::<String>()
        )
    }
}

fn account_label(accounts: &[AccountMeta], id: AccountId) -> String {
    accounts
        .iter()
        .find(|a| a.id == id)
        .map_or_else(|| "(removed account)".into(), |a| a.label.clone())
}

/// Draws the whole UI and returns the commands the user triggered.
pub fn ui(root: &mut egui::Ui, snap: &Snapshot, st: &mut UiState) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    let unlocked = snap.authed
        && snap
            .status
            .as_ref()
            .is_some_and(|s| s.vault == VaultState::Unlocked);

    // Top bar: status at a glance.
    egui::Panel::top("top").show(root, |ui| {
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("Embr").heading().color(EMBER).strong());
            ui.separator();
            match (&snap.daemon_down, &snap.status) {
                (Some(_), _) => badge(ui, "daemon not running", BAD),
                (None, Some(s)) => match s.vault {
                    VaultState::Unlocked if unlocked => badge(ui, "unlocked", OK_GREEN),
                    VaultState::Unlocked => badge(ui, "unlocked elsewhere", WARN),
                    VaultState::Locked => badge(ui, "locked", WARN),
                    VaultState::Missing => badge(ui, "no vault", WARN),
                },
                _ => {}
            }
            if unlocked {
                if let Some(active) = snap
                    .active
                    .and_then(|id| snap.accounts.iter().find(|a| a.id == id))
                {
                    ui.label(format!("Active: {}", active.label));
                }
                if let Some(secs) = snap.status.as_ref().and_then(|s| s.locks_in_secs) {
                    ui.label(RichText::new(format!("auto-locks in {}", fmt_secs(secs))).weak());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Lock now").clicked() {
                        cmds.push(Cmd::Lock);
                    }
                });
            }
        });
    });

    if let Some(n) = &snap.notice {
        egui::Panel::bottom("notice").show(root, |ui| {
            ui.colored_label(if n.error { BAD } else { OK_GREEN }, &n.text);
        });
    }

    if !unlocked {
        // On the lock screen only the unlock fields are live; wipe the others (and, once the vault is
        // already unlocked elsewhere, nothing typed here is kept either).
        let (pw, pw2) = (
            std::mem::take(&mut st.password),
            std::mem::take(&mut st.password2),
        );
        st.wipe_secrets();
        (st.password, st.password2) = (pw, pw2);
        egui::CentralPanel::default().show(root, |ui| lock_screen(ui, snap, st, &mut cmds));
        return cmds;
    }

    egui::Panel::left("nav")
        .resizable(false)
        .exact_size(170.0)
        .show(root, |ui| {
            ui.add_space(8.0);
            let pending = snap.pending.len();
            for (screen, label) in [
                (Screen::Dashboard, "Dashboard".to_owned()),
                (
                    Screen::Approvals,
                    if pending > 0 {
                        format!("Approvals  ({pending})")
                    } else {
                        "Approvals".into()
                    },
                ),
                (Screen::Accounts, "Accounts".into()),
                (Screen::Apps, "Applications".into()),
                (Screen::Remote, "Remote signing".into()),
                (Screen::Settings, "Settings".into()),
                (Screen::Activity, "Activity".into()),
            ] {
                let text = if screen == Screen::Approvals && pending > 0 {
                    RichText::new(label).color(EMBER).strong()
                } else {
                    RichText::new(label)
                };
                if ui.selectable_label(st.screen == screen, text).clicked() {
                    st.screen = screen;
                }
            }
        });

    egui::CentralPanel::default().show(root, |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| match st.screen {
                Screen::Dashboard => dashboard(ui, snap, st),
                Screen::Approvals => approvals(ui, snap, st, &mut cmds),
                Screen::Accounts => accounts(ui, snap, st, &mut cmds),
                Screen::Apps => apps(ui, snap, &mut cmds),
                Screen::Remote => remote(ui, snap, st, &mut cmds),
                Screen::Settings => settings(ui, snap, st, &mut cmds),
                Screen::Activity => activity(ui, snap),
            });
    });
    cmds
}

fn fmt_secs(s: u64) -> String {
    if s >= 3600 {
        format!("{} h {} min", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

fn lock_screen(ui: &mut egui::Ui, snap: &Snapshot, st: &mut UiState, cmds: &mut Vec<Cmd>) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.18);
        ui.label(RichText::new("Embr").size(34.0).color(EMBER).strong());
        ui.label(RichText::new("Your Nostr keys stay here. Apps ask; you decide.").weak());
        ui.add_space(18.0);
        if let Some(why) = &snap.daemon_down {
            ui.colored_label(BAD, "The signer daemon (embrd) is not running.");
            ui.label(RichText::new(why).weak().small());
            ui.add_space(8.0);
            if ui.button("Start the daemon").clicked() {
                cmds.push(Cmd::StartDaemon);
            }
            return;
        }
        let missing = snap.status.as_ref().is_some_and(|s| s.vault == VaultState::Missing);
        ui.set_max_width(340.0);
        ui.label(if missing { "Create a vault: choose a strong password (at least 10 characters)." } else { "Enter your vault password to unlock." });
        let resp = ui.add(egui::TextEdit::singleline(&mut st.password).password(true).hint_text("Vault password").desired_width(300.0));
        let mut submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if missing {
            ui.add(egui::TextEdit::singleline(&mut st.password2).password(true).hint_text("Repeat password").desired_width(300.0));
        }
        ui.add_space(6.0);
        if ui.add(egui::Button::new(if missing { "Create vault" } else { "Unlock" }).fill(EMBER.gamma_multiply(0.35))).clicked() {
            submit = true;
        }
        if missing {
            ui.label(RichText::new("There is no way to recover a forgotten password: keep a NIP-49 export of your keys.").small().color(WARN));
        }
        if submit && !st.password.is_empty() {
            if missing {
                if st.password == st.password2 {
                    cmds.push(Cmd::CreateVault(std::mem::take(&mut st.password)));
                    st.password2.clear();
                }
            } else {
                cmds.push(Cmd::Unlock(std::mem::take(&mut st.password)));
            }
        }
    });
}

fn dashboard(ui: &mut egui::Ui, snap: &Snapshot, st: &mut UiState) {
    ui.heading("Dashboard");
    ui.add_space(6.0);
    let Some(s) = &snap.status else { return };
    // Three equal tiles side by side; their text wraps inside them on a narrow window.
    let gap = ui.spacing().item_spacing.x;
    let w = ((ui.available_width() - 2.0 * gap - 3.0 * 26.0) / 3.0).max(120.0);
    ui.horizontal_top(|ui| {
        tile(ui, w, |ui| {
            ui.label(RichText::new("Vault").strong());
            ui.colored_label(OK_GREEN, "Unlocked");
            ui.label(
                RichText::new(if s.lock_timeout_secs == 0 {
                    "Auto-lock: never".to_owned()
                } else {
                    format!("Auto-lock after {} idle", fmt_secs(s.lock_timeout_secs))
                })
                .weak(),
            );
        });
        tile(ui, w, |ui| {
            ui.label(RichText::new("Local signer").strong());
            ui.colored_label(OK_GREEN, "Running");
            ui.label(RichText::new("Native apps on this computer").weak());
        });
        tile(ui, w, |ui| {
            ui.label(RichText::new("Remote signing (NIP-46)").strong());
            if s.remote_signing_enabled {
                let connected = snap.nip46.as_ref().map_or(0, |n| {
                    n.relays.iter().filter(|r| r.state == "connected").count()
                });
                ui.colored_label(OK_GREEN, format!("On — {connected} relay(s) connected"));
            } else {
                ui.label("Off (default)");
            }
        });
    });
    ui.add_space(10.0);
    let pending = snap.pending.len();
    if pending > 0 {
        card(ui, Some(EMBER), |ui| {
            ui.label(
                RichText::new(format!("{pending} request(s) waiting for your decision"))
                    .color(EMBER)
                    .strong(),
            );
            if ui.button("Review now").clicked() {
                st.screen = Screen::Approvals;
            }
        });
    } else {
        ui.label(RichText::new("Nothing is waiting for you.").weak());
    }
    ui.add_space(10.0);
    ui.label(RichText::new("Identities").strong());
    if snap.accounts.is_empty() {
        ui.label("No identities yet — add or import one under Accounts.");
    }
    for a in &snap.accounts {
        ui.label(format!(
            "{}{}   {}",
            if Some(a.id) == snap.active {
                "● "
            } else {
                "   "
            },
            a.label,
            short(&a.npub)
        ));
    }
}

// ---- approvals ---------------------------------------------------------------------------

/// What the policy engine will accept for a request, so the UI never offers a choice that the daemon
/// would refuse (`embr_policy::Engine::validate_choice` is the authority; this only mirrors it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Limits {
    /// Direct-message kinds: once or this session only.
    sensitive: bool,
    /// "Every kind of event" is ticked: never persistent.
    any_kind: bool,
    /// Decryption that is not tied to one peer: at most an hour.
    unscoped_decrypt: bool,
}

impl Limits {
    fn of(view: &PendingView, c: &Choice) -> Self {
        Self {
            sensitive: view.event.as_ref().is_some_and(|e| e.sensitive),
            any_kind: c.any_kind,
            unscoped_decrypt: view.reveals_plaintext && view.peer.is_none(),
        }
    }
}

fn duration_allowed(d: Duration, l: Limits) -> bool {
    match d {
        Duration::Once | Duration::Session => true,
        Duration::Min15 | Duration::Hour1 => !l.sensitive,
        Duration::Always => !l.sensitive && !l.any_kind && !l.unscoped_decrypt,
    }
}

/// The longest allowed choice at or below the current one, so a toggle never leaves an invalid state.
fn clamp_duration(c: &mut Choice, l: Limits) {
    for d in [
        c.duration,
        Duration::Hour1,
        Duration::Session,
        Duration::Once,
    ] {
        if duration_allowed(d, l) {
            c.duration = d;
            return;
        }
    }
}

fn duration_ui(ui: &mut egui::Ui, c: &mut Choice, l: Limits) {
    ui.label("Remember this decision:");
    ui.horizontal_wrapped(|ui| {
        for (d, label) in [
            (Duration::Once, "Just this once"),
            (Duration::Session, "While the app is connected"),
            (Duration::Min15, "15 minutes"),
            (Duration::Hour1, "1 hour"),
            (Duration::Always, "Until I revoke it"),
        ] {
            ui.add_enabled_ui(duration_allowed(d, l), |ui| {
                ui.selectable_value(&mut c.duration, d, label);
            });
        }
    });
}

fn decision_of(view: &PendingView, c: &Choice) -> (DecisionWire, Option<ScopeWire>) {
    let decision = match c.duration {
        Duration::Once => DecisionWire::AllowOnce,
        Duration::Session => DecisionWire::AllowSession,
        Duration::Min15 => DecisionWire::AllowUntil { until: now() + 900 },
        Duration::Hour1 => DecisionWire::AllowUntil {
            until: now() + 3600,
        },
        Duration::Always => DecisionWire::AllowPersistent,
    };
    let scope = (c.duration != Duration::Once).then_some(ScopeWire {
        kind: match (&view.event, c.any_kind) {
            (Some(ev), false) => KindScope::Exact(ev.kind),
            _ => KindScope::Any,
        },
        peer: view.peer,
        uses: None,
    });
    (decision, scope)
}

fn approvals(ui: &mut egui::Ui, snap: &Snapshot, st: &mut UiState, cmds: &mut Vec<Cmd>) {
    ui.heading("Approvals");
    if snap.pending.is_empty() {
        ui.add_space(8.0);
        ui.label("No requests are waiting. When an app asks to sign or decrypt something, it appears here.");
        return;
    }
    for view in &snap.pending {
        ui.add_space(8.0);
        pending_card(ui, snap, st, view, cmds);
    }
}

fn pending_card(
    ui: &mut egui::Ui,
    snap: &Snapshot,
    st: &mut UiState,
    view: &PendingView,
    cmds: &mut Vec<Cmd>,
) {
    let choice = st.choices.entry(view.id).or_default();
    let sensitive = view.event.as_ref().is_some_and(|e| e.sensitive);
    let accent = if view.reveals_plaintext || sensitive {
        WARN
    } else {
        EMBER
    };
    card(ui, Some(accent), |ui| {
        ui.horizontal_wrapped(|ui| {
            match view.kind {
                PendingKind::Pair => ui.label(RichText::new("New app wants to connect").heading()),
                PendingKind::Operation => ui.label(
                    RichText::new(
                        view.operation
                            .as_deref()
                            .map_or("Request".to_owned(), operation_title),
                    )
                    .heading(),
                ),
            };
            if view.client.via == "nip46" {
                badge(ui, "remote (NIP-46)", EMBER);
            }
            if view.legacy {
                badge(ui, "LEGACY NIP-04", WARN);
            }
            if view.reveals_plaintext {
                badge(ui, "returns private text", WARN);
            }
        });
        egui::Grid::new(("who", view.id))
            .num_columns(2)
            .spacing([14.0, 3.0])
            .show(ui, |ui| {
                ui.label("From");
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&view.client.name).strong());
                    ui.label(
                        RichText::new("(name is self-declared, unverified)")
                            .weak()
                            .small(),
                    );
                });
                ui.end_row();
                ui.label("App key");
                ui.label(RichText::new(short(&view.client.pubkey.to_string())).monospace());
                ui.end_row();
                if let Some(p) = &view.client.peer {
                    ui.label("Process");
                    ui.label(
                        RichText::new(format!(
                            "pid {}{} — a hint only, can be spoofed",
                            p.pid.map_or("?".into(), |x| x.to_string()),
                            p.exe
                                .as_deref()
                                .map(|e| format!(", {e}"))
                                .unwrap_or_default()
                        ))
                        .small()
                        .weak(),
                    );
                    ui.end_row();
                }
                if let Some(a) = &view.account {
                    ui.label("Identity");
                    ui.label(format!("{}  ({})", a.label, short(&a.npub)));
                    ui.end_row();
                }
            });
        ui.add_space(4.0);

        if let Some(ev) = &view.event {
            ui.label(
                RichText::new(format!("Sign a {} (kind {})", kind_name(ev.kind), ev.kind)).strong(),
            );
            if ev.sensitive {
                ui.colored_label(
                    WARN,
                    "Direct-message data: this can only be allowed once or for this session.",
                );
            }
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(&ev.content).monospace());
                if ev.content_len > ev.content.len() {
                    ui.label(
                        RichText::new(format!("({} bytes in total)", ev.content_len))
                            .weak()
                            .small(),
                    );
                }
            });
            for t in &ev.tags {
                ui.label(
                    RichText::new(format!("tag: {}", t.join("  ·  ")))
                        .monospace()
                        .small(),
                );
            }
            if ev.tags_total > ev.tags.len() {
                ui.label(
                    RichText::new(format!("… and {} more tags", ev.tags_total - ev.tags.len()))
                        .weak()
                        .small(),
                );
            }
        }
        if let Some(p) = view.peer {
            ui.label(format!("With: {}", short(&p.to_string())));
        }
        if let Some(t) = &view.text_preview {
            ui.label(RichText::new(t).monospace());
        }
        if view.reveals_plaintext {
            ui.colored_label(WARN, "Approving hands the decrypted private text to this app. Decryption is a separate permission from signing.");
        }
        if view.kind == PendingKind::Pair && !view.requested_permissions.is_empty() {
            ui.label(
                RichText::new(format!(
                    "It asks for: {} (a wish, not a grant — every request is still checked)",
                    view.requested_permissions.join(", ")
                ))
                .small(),
            );
        }
        ui.add_space(6.0);
        ui.separator();

        match view.kind {
            PendingKind::Pair => {
                let fixed = view.account.as_ref().map(|a| a.id);
                let account = choice
                    .account
                    .or(fixed)
                    .or(snap.active)
                    .or_else(|| snap.accounts.first().map(|a| a.id));
                ui.horizontal(|ui| {
                    ui.label("Use identity:");
                    egui::ComboBox::from_id_salt(("pairacct", view.id))
                        .selected_text(
                            account.map_or("—".into(), |id| account_label(&snap.accounts, id)),
                        )
                        .show_ui(ui, |ui| {
                            for a in &snap.accounts {
                                if fixed.is_none_or(|f| f == a.id) {
                                    ui.selectable_value(&mut choice.account, Some(a.id), &a.label);
                                }
                            }
                        });
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            account.is_some(),
                            egui::Button::new("Approve").fill(OK_GREEN.gamma_multiply(0.5)),
                        )
                        .clicked()
                        && let Some(account) = account
                    {
                        cmds.push(Cmd::Decide {
                            view: Box::new(view.clone()),
                            decision: DecisionWire::Pair { account },
                            scope: None,
                        });
                    }
                    if ui.button("Reject").clicked() {
                        cmds.push(Cmd::Decide {
                            view: Box::new(view.clone()),
                            decision: DecisionWire::RejectOnce,
                            scope: None,
                        });
                    }
                    if ui.button("Block this app").clicked() {
                        cmds.push(Cmd::Decide {
                            view: Box::new(view.clone()),
                            decision: DecisionWire::BlockClient,
                            scope: None,
                        });
                    }
                });
            }
            PendingKind::Operation => {
                duration_ui(ui, choice, Limits::of(view, choice));
                if view.event.is_some() && choice.duration != Duration::Once && !sensitive {
                    ui.checkbox(
                        &mut choice.any_kind,
                        "Apply to every kind of event (except direct messages), not just this one",
                    );
                    if choice.any_kind {
                        ui.label(
                            RichText::new("Permissions for every kind last at most 24 hours.")
                                .weak()
                                .small(),
                        );
                    }
                }
                clamp_duration(choice, Limits::of(view, choice));
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new("Approve").fill(OK_GREEN.gamma_multiply(0.5)))
                        .clicked()
                    {
                        let (decision, scope) = decision_of(view, choice);
                        cmds.push(Cmd::Decide {
                            view: Box::new(view.clone()),
                            decision,
                            scope,
                        });
                    }
                    if ui.button("Reject").clicked() {
                        cmds.push(Cmd::Decide {
                            view: Box::new(view.clone()),
                            decision: DecisionWire::RejectOnce,
                            scope: None,
                        });
                    }
                    if ui.button("Always reject").clicked() {
                        let scope = Some(ScopeWire {
                            kind: view
                                .event
                                .as_ref()
                                .map_or(KindScope::Any, |e| KindScope::Exact(e.kind)),
                            peer: view.peer,
                            uses: None,
                        });
                        cmds.push(Cmd::Decide {
                            view: Box::new(view.clone()),
                            decision: DecisionWire::AlwaysReject,
                            scope,
                        });
                    }
                    if ui.button("Block this app").clicked() {
                        cmds.push(Cmd::Decide {
                            view: Box::new(view.clone()),
                            decision: DecisionWire::BlockClient,
                            scope: None,
                        });
                    }
                });
            }
        }
        ui.label(
            RichText::new(format!(
                "Expires in {}",
                fmt_secs(view.expires_at.saturating_sub(now()))
            ))
            .weak()
            .small(),
        );
    });
}

fn operation_title(op: &str) -> String {
    match op {
        "sign_event" => "Sign an event",
        "nip44_encrypt" => "Encrypt a message (NIP-44)",
        "nip44_decrypt" => "Decrypt a message (NIP-44)",
        "nip04_encrypt" => "Encrypt a message (legacy NIP-04)",
        "nip04_decrypt" => "Decrypt a message (legacy NIP-04)",
        other => other,
    }
    .to_owned()
}

// ---- accounts ----------------------------------------------------------------------------

fn accounts(ui: &mut egui::Ui, snap: &Snapshot, st: &mut UiState, cmds: &mut Vec<Cmd>) {
    ui.heading("Accounts");
    ui.label(
        RichText::new(
            "Your private keys never leave the signer. The app only ever sees public information.",
        )
        .weak(),
    );
    ui.add_space(6.0);
    for a in &snap.accounts {
        card(
            ui,
            if Some(a.id) == snap.active {
                Some(EMBER)
            } else {
                None
            },
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&a.label).strong().size(16.0));
                    if Some(a.id) == snap.active {
                        badge(ui, "active", EMBER);
                    }
                    badge(
                        ui,
                        &format!("key {:?}", a.key_security).to_lowercase(),
                        if format!("{:?}", a.key_security) == "Weak" {
                            WARN
                        } else {
                            OK_GREEN
                        },
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&a.npub).monospace().small());
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(a.npub.clone());
                    }
                });
                ui.horizontal(|ui| {
                    if Some(a.id) != snap.active && ui.button("Make active").clicked() {
                        cmds.push(Cmd::SetActive(a.id));
                    }
                    if ui.button("Rename").clicked() {
                        st.rename = Some((a.id, a.label.clone()));
                    }
                    if ui.button("Export (NIP-49)").clicked() {
                        st.export = Some((a.id, String::new(), String::new()));
                    }
                    if ui.button("Remove…").clicked() {
                        st.confirm_remove = Some((a.id, String::new()));
                    }
                });
            },
        );
        ui.add_space(4.0);
    }
    if let Some((id, label)) = &mut st.rename {
        let id = *id;
        let (mut save, mut cancel) = (false, false);
        card(ui, None, |ui| {
            ui.label("New label:");
            ui.text_edit_singleline(label);
            ui.horizontal(|ui| {
                save = ui.button("Save").clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if save {
            cmds.push(Cmd::Rename(id, label.clone()));
        }
        if save || cancel {
            st.rename = None;
        }
    }
    if let Some((id, vpw, epw)) = &mut st.export {
        let id = *id;
        let (mut export, mut close) = (false, false);
        card(ui, None, |ui| {
            ui.label(
                RichText::new("Export an encrypted copy of this key (NIP-49 ncryptsec)").strong(),
            );
            ui.label("Needs your vault password again, and a password to protect the export. Store the export somewhere safe, and the password somewhere else.");
            ui.add(
                egui::TextEdit::singleline(vpw)
                    .password(true)
                    .hint_text("Vault password"),
            );
            ui.add(
                egui::TextEdit::singleline(epw)
                    .password(true)
                    .hint_text("Password for the export"),
            );
            if let Some(enc) = &snap.exported {
                ui.label(RichText::new(enc).monospace().small());
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(enc.clone());
                }
            }
            ui.horizontal(|ui| {
                export = ui.button("Export").clicked();
                close = ui.button("Close").clicked();
            });
        });
        if export && !vpw.is_empty() && !epw.is_empty() {
            cmds.push(Cmd::Export {
                id,
                vault_password: std::mem::take(vpw),
                export_password: std::mem::take(epw),
            });
        }
        if close {
            st.export = None;
        }
    }
    if let Some((id, typed)) = &mut st.confirm_remove {
        let id = *id;
        let label = account_label(&snap.accounts, id);
        let (mut delete, mut cancel) = (false, false);
        card(ui, Some(BAD), |ui| {
            ui.colored_label(
                BAD,
                format!("Delete “{label}” and its private key permanently?"),
            );
            ui.label("Without a NIP-49 export you cannot get this identity back. Apps paired to it lose access. Type the label to confirm:");
            ui.text_edit_singleline(typed);
            ui.horizontal(|ui| {
                delete = ui
                    .add_enabled(*typed == label, egui::Button::new("Delete forever"))
                    .clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if delete {
            cmds.push(Cmd::Remove(id));
        }
        if delete || cancel {
            st.confirm_remove = None;
        }
    }

    ui.add_space(10.0);
    ui.label(RichText::new("Add an identity").strong());
    card(ui, None, |ui| {
        ui.label("Generate a new key inside the vault:");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut st.new_label)
                    .hint_text("Label")
                    .desired_width(200.0),
            );
            if ui
                .add_enabled(
                    !st.new_label.trim().is_empty(),
                    egui::Button::new("Generate"),
                )
                .clicked()
            {
                cmds.push(Cmd::AddGenerated(std::mem::take(&mut st.new_label)));
            }
        });
        ui.separator();
        ui.label("Import an existing key (nsec / hex) or a NIP-49 backup (ncryptsec):");
        ui.add(
            egui::TextEdit::singleline(&mut st.import_label)
                .hint_text("Label")
                .desired_width(200.0),
        );
        ui.add(
            egui::TextEdit::singleline(&mut st.import_secret)
                .password(true)
                .hint_text("nsec1… / hex / ncryptsec1…")
                .desired_width(420.0),
        );
        let is_enc = st.import_secret.trim().starts_with("ncryptsec1");
        if is_enc {
            ui.add(
                egui::TextEdit::singleline(&mut st.import_password)
                    .password(true)
                    .hint_text("Password of the backup")
                    .desired_width(300.0),
            );
        } else if !st.import_secret.is_empty() {
            ui.label(
                RichText::new("A key pasted as text is recorded as handled insecurely.")
                    .small()
                    .color(WARN),
            );
        }
        if ui
            .add_enabled(
                !st.import_label.trim().is_empty() && !st.import_secret.is_empty(),
                egui::Button::new("Import"),
            )
            .clicked()
        {
            let label = std::mem::take(&mut st.import_label);
            let secret = std::mem::take(&mut st.import_secret);
            cmds.push(if is_enc {
                Cmd::ImportNcryptsec {
                    label,
                    ncryptsec: secret,
                    password: std::mem::take(&mut st.import_password),
                }
            } else {
                Cmd::ImportSecret { label, secret }
            });
        }
    });
    ui.add_space(10.0);
    ui.label(RichText::new("Backup").strong());
    card(ui, None, |ui| {
        ui.label("An encrypted copy of the whole vault (all accounts, permissions), protected by the current vault password.");
        ui.add(
            egui::TextEdit::singleline(&mut st.backup_path)
                .hint_text("Absolute path of a new file, e.g. /home/me/embr-backup.embr")
                .desired_width(460.0),
        );
        if ui
            .add_enabled(
                !st.backup_path.trim().is_empty(),
                egui::Button::new("Write backup"),
            )
            .clicked()
        {
            cmds.push(Cmd::Backup(st.backup_path.trim().to_owned()));
        }
    });
}

// ---- applications -----------------------------------------------------------------------

fn apps(ui: &mut egui::Ui, snap: &Snapshot, cmds: &mut Vec<Cmd>) {
    ui.heading("Applications");
    ui.label(RichText::new("Apps you approved. Each has its own permissions; nothing is allowed that you did not allow.").weak());
    if snap.clients.is_empty() {
        ui.add_space(8.0);
        ui.label("No application is paired yet.");
    }
    for c in &snap.clients {
        ui.add_space(6.0);
        card(ui, None, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&c.record.name).strong().size(16.0));
                ui.label(RichText::new("(self-declared)").weak().small());
                if c.record.via == "nip46" {
                    badge(ui, "remote", EMBER);
                }
                if c.connected > 0 {
                    badge(ui, "connected", OK_GREEN);
                }
            });
            ui.label(
                RichText::new(short(&c.record.key.to_string()))
                    .monospace()
                    .small(),
            );
            ui.label(format!(
                "Uses: {}",
                c.record
                    .accounts
                    .iter()
                    .map(|id| account_label(&snap.accounts, *id))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            let grants: Vec<_> = snap
                .grants
                .iter()
                .filter(|g| g.client == c.record.key)
                .collect();
            if grants.is_empty() {
                ui.label(RichText::new("No remembered permissions: it asks every time.").weak());
            }
            for g in grants {
                ui.horizontal(|ui| {
                    let kind = match g.kind {
                        KindScope::Any => "any kind".to_owned(),
                        KindScope::Exact(k) => format!("kind {k} ({})", kind_name(k)),
                    };
                    let when = match g.expiry {
                        embr_policy::Expiry::Session(_) => "this session".to_owned(),
                        embr_policy::Expiry::Until(t) => {
                            format!("for {}", fmt_secs(t.saturating_sub(now())))
                        }
                        embr_policy::Expiry::Never => "until revoked".to_owned(),
                    };
                    let allow = matches!(g.effect, embr_policy::Effect::Allow);
                    ui.colored_label(
                        if allow { OK_GREEN } else { BAD },
                        if allow { "Allow" } else { "Always reject" },
                    );
                    ui.label(format!("{} · {} · {}", g.op, kind, when));
                    if ui.small_button("Revoke").clicked() {
                        cmds.push(Cmd::RevokeGrant(g.id.0));
                    }
                });
            }
            ui.horizontal(|ui| {
                if ui.button("Disconnect (forget this app)").clicked() {
                    cmds.push(Cmd::RevokeClient(c.record.key));
                }
                if ui.button("Block").clicked() {
                    cmds.push(Cmd::BlockClient(c.record.key));
                }
            });
        });
    }
}

// ---- remote signing ---------------------------------------------------------------------

fn remote(ui: &mut egui::Ui, snap: &Snapshot, st: &mut UiState, cmds: &mut Vec<Cmd>) {
    ui.heading("Remote signing (NIP-46)");
    ui.label(RichText::new("Lets web or phone apps ask this signer over Nostr relays. Off by default: nothing touches the network until you turn it on.").weak());
    ui.add_space(6.0);
    let Some(settings) = &snap.settings else {
        return;
    };
    card(ui, None, |ui| {
        let mut enabled = settings.remote_signing_enabled;
        if ui.checkbox(&mut enabled, "Enable remote signing").changed() {
            let mut s = settings.clone();
            s.remote_signing_enabled = enabled;
            cmds.push(Cmd::SetSettings(s));
        }
        ui.label(RichText::new("Relays").strong());
        if settings.relays.is_empty() {
            ui.label(
                RichText::new(
                    "No relays yet. Add at least one (wss://…, or ws://localhost for testing).",
                )
                .weak(),
            );
        }
        for r in &settings.relays {
            ui.horizontal(|ui| {
                let state = snap.nip46.as_ref().and_then(|n| {
                    n.relays
                        .iter()
                        .find(|x| x.url.trim_end_matches('/') == r.trim_end_matches('/'))
                });
                match state.map(|s| s.state.as_str()) {
                    Some("connected") => ui.colored_label(OK_GREEN, "●"),
                    Some("failed") => ui.colored_label(BAD, "●"),
                    Some(_) => ui.colored_label(WARN, "●"),
                    None => ui.label("○"),
                };
                ui.label(RichText::new(r).monospace());
                if let Some(d) = state.and_then(|s| s.detail.as_deref()) {
                    ui.label(RichText::new(d).small().color(BAD));
                }
                if ui.small_button("Remove").clicked() {
                    let mut s = settings.clone();
                    s.relays.retain(|x| x != r);
                    cmds.push(Cmd::SetSettings(s));
                }
            });
        }
        if state_blocked(snap) {
            ui.colored_label(WARN, "The service sandbox blocks network sockets: install the drop-in from docs/NIP46.md and restart embrd.");
        }
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut st.new_relay)
                    .hint_text("wss://relay.example.com")
                    .desired_width(300.0),
            );
            if ui
                .add_enabled(
                    !st.new_relay.trim().is_empty(),
                    egui::Button::new("Add relay"),
                )
                .clicked()
            {
                let mut s = settings.clone();
                s.relays
                    .push(std::mem::take(&mut st.new_relay).trim().to_owned());
                cmds.push(Cmd::SetSettings(s));
            }
        });
    });
    ui.add_space(8.0);
    let account = st
        .remote_account
        .or(snap.active)
        .or_else(|| snap.accounts.first().map(|a| a.id));
    card(ui, None, |ui| {
        ui.label(RichText::new("Connect an app").strong());
        ui.horizontal(|ui| {
            ui.label("Identity:");
            egui::ComboBox::from_id_salt("remote_acct")
                .selected_text(account.map_or("—".into(), |id| account_label(&snap.accounts, id)))
                .show_ui(ui, |ui| {
                    for a in &snap.accounts {
                        ui.selectable_value(&mut st.remote_account, Some(a.id), &a.label);
                    }
                });
        });
        ui.label("1. The app shows a nostrconnect:// link: paste it here.");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut st.nostrconnect)
                    .hint_text("nostrconnect://…")
                    .desired_width(420.0),
            );
            if ui
                .add_enabled(
                    account.is_some()
                        && settings.remote_signing_enabled
                        && !st.nostrconnect.trim().is_empty(),
                    egui::Button::new("Import"),
                )
                .clicked()
                && let Some(account) = account
            {
                cmds.push(Cmd::NostrConnect {
                    uri: std::mem::take(&mut st.nostrconnect).trim().to_owned(),
                    account,
                });
            }
        });
        ui.label("2. Or create a single-use bunker:// link (valid 10 minutes) and paste it into the app:");
        if ui
            .add_enabled(
                account.is_some() && settings.remote_signing_enabled && !settings.relays.is_empty(),
                egui::Button::new("Create bunker link"),
            )
            .clicked()
            && let Some(account) = account
        {
            cmds.push(Cmd::Bunker(account));
        }
        if let Some(uri) = &snap.bunker_uri {
            ui.label(RichText::new(uri).monospace().small());
            ui.horizontal(|ui| {
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(uri.clone());
                }
            });
            qr(ui, uri);
            ui.label(
                RichText::new("The app will then appear under Approvals for you to accept.")
                    .weak()
                    .small(),
            );
        }
    });
}

fn state_blocked(snap: &Snapshot) -> bool {
    snap.nip46.as_ref().is_some_and(|n| {
        n.relays.iter().any(|r| {
            r.detail
                .as_deref()
                .is_some_and(|d| d.contains("Address family not supported"))
        })
    })
}

/// Draws a QR code with plain rectangles.
fn qr(ui: &mut egui::Ui, text: &str) {
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else {
        return;
    };
    let w = code.width();
    let cell = 4.0;
    let quiet = 2.0 * cell;
    let size = egui::vec2(w as f32 * cell + 2.0 * quiet, w as f32 * cell + 2.0 * quiet);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, Color32::WHITE);
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == qrcode::Color::Dark {
            let (x, y) = ((i % w) as f32, (i / w) as f32);
            let p = rect.min + egui::vec2(quiet + x * cell, quiet + y * cell);
            painter.rect_filled(
                egui::Rect::from_min_size(p, egui::vec2(cell, cell)),
                0.0,
                Color32::BLACK,
            );
        }
    }
}

// ---- settings & activity ----------------------------------------------------------------

fn settings(ui: &mut egui::Ui, snap: &Snapshot, st: &mut UiState, cmds: &mut Vec<Cmd>) {
    ui.heading("Settings");
    let Some(current) = &snap.settings else {
        return;
    };
    let draft = st.settings_draft.get_or_insert_with(|| current.clone());
    let mut reset = false;
    card(ui, None, |ui| {
        ui.label(RichText::new("Security").strong());
        let mut minutes = draft.lock_timeout_secs / 60;
        let mut never = draft.lock_timeout_secs == 0;
        ui.checkbox(&mut never, "Never lock automatically (not recommended)");
        if !never {
            if minutes == 0 {
                minutes = 15;
            }
            ui.horizontal(|ui| {
                ui.label("Lock after");
                ui.add(egui::Slider::new(&mut minutes, 1..=240).suffix(" min idle"));
            });
        }
        draft.lock_timeout_secs = if never { 0 } else { minutes * 60 };
        ui.label(
            RichText::new("Idle time counts your own activity here, not requests from apps.")
                .weak()
                .small(),
        );
        ui.checkbox(
            &mut draft.notifications,
            "Desktop notifications for approval requests (never include message content)",
        );
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                let mut s = current.clone();
                s.lock_timeout_secs = draft.lock_timeout_secs;
                s.notifications = draft.notifications;
                cmds.push(Cmd::SetSettings(s));
            }
            reset = ui.button("Reset").clicked();
        });
    });
    if reset {
        st.settings_draft = Some(current.clone());
    }
    ui.add_space(8.0);
    card(ui, None, |ui| {
        ui.label(RichText::new("Change vault password").strong());
        ui.add(
            egui::TextEdit::singleline(&mut st.pw_old)
                .password(true)
                .hint_text("Current password"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut st.pw_new)
                .password(true)
                .hint_text("New password (at least 10 characters)"),
        );
        if ui
            .add_enabled(
                !st.pw_old.is_empty() && st.pw_new.chars().count() >= 10,
                egui::Button::new("Change password"),
            )
            .clicked()
        {
            cmds.push(Cmd::ChangePassword {
                old: std::mem::take(&mut st.pw_old),
                new: std::mem::take(&mut st.pw_new),
            });
        }
        ui.label(
            RichText::new(
                "Copies of the vault made before the change still open with the old password.",
            )
            .weak()
            .small(),
        );
    });
    ui.add_space(8.0);
    card(ui, None, |ui| {
        ui.label(RichText::new("About").strong());
        ui.label(format!(
            "Embr signer daemon {}",
            snap.status.as_ref().map_or("?", |s| s.version.as_str())
        ));
        ui.label(RichText::new("Pre-alpha software; not independently audited. No telemetry, no analytics, no cloud.").weak().small());
    });
}

fn activity(ui: &mut egui::Ui, snap: &Snapshot) {
    ui.heading("Activity");
    ui.label(RichText::new("Metadata only: who asked for what, and what happened. Never keys, messages or signatures.").weak());
    ui.add_space(6.0);
    if snap.log.is_empty() {
        ui.label("Nothing yet.");
    }
    for r in snap.log.iter().rev() {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(fmt_ago(now().saturating_sub(r.ts)))
                    .weak()
                    .small(),
            );
            ui.label(RichText::new(r.via.as_str()).small());
            ui.label(RichText::new(&r.action).strong());
            if let Some(k) = r.kind {
                ui.label(format!("kind {k}"));
            }
            if let Some(n) = &r.client_name {
                ui.label(n);
            }
            let (text, color) = outcome_label(r.outcome);
            ui.label(RichText::new(text).color(color));
        });
    }
}

/// Human wording and colour for an audit outcome. Exhaustive on purpose: a new variant must be
/// given a label here instead of leaking its Rust name into the UI.
fn outcome_label(o: embr_policy::AuditOutcome) -> (&'static str, Color32) {
    use embr_policy::AuditOutcome as O;
    match o {
        O::AllowedByGrant => ("allowed by a saved permission", OK_GREEN),
        O::AllowedByUser => ("allowed by you", OK_GREEN),
        O::DeniedByGrant => ("denied by a saved rule", BAD),
        O::DeniedByUser => ("denied by you", BAD),
        O::Refused => ("refused", BAD),
        O::RateLimited => ("rate limited", BAD),
        O::Expired => ("expired unanswered", WARN),
        O::Cancelled => ("cancelled", WARN),
        O::Paired => ("paired", OK_GREEN),
        O::Revoked => ("permission revoked", WARN),
        O::Admin => ("vault event", WARN),
    }
}

fn fmt_ago(s: u64) -> String {
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86_400)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::demo;
    use embr_core::Operation;
    use embr_policy::{Choice as PolicyChoice, Engine, Request, Scope};

    const ALL_SCREENS: [Screen; 7] = [
        Screen::Dashboard,
        Screen::Approvals,
        Screen::Accounts,
        Screen::Apps,
        Screen::Remote,
        Screen::Settings,
        Screen::Activity,
    ];

    /// Every string the frame draws.
    fn texts(out: &egui::FullOutput) -> String {
        fn walk(shape: &egui::Shape, acc: &mut String) {
            match shape {
                egui::Shape::Text(t) => {
                    acc.push_str(t.galley.text());
                    acc.push('\n');
                }
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, acc)),
                _ => {}
            }
        }
        let mut acc = String::new();
        out.shapes.iter().for_each(|c| walk(&c.shape, &mut acc));
        acc
    }

    /// Runs the UI headless for two frames (the first only lays out) and returns what the user would
    /// see plus the commands it emitted.
    fn render(snap: &Snapshot, st: &mut UiState) -> (String, Vec<Cmd>) {
        let ctx = egui::Context::default();
        let mut cmds = Vec::new();
        let mut seen = String::new();
        for _ in 0..2 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(980.0, 680.0),
                )),
                ..Default::default()
            };
            cmds.clear();
            let mut out = ctx.run_ui(input, |root| cmds = ui(root, snap, st));
            seen = texts(&out);
            // No renderer consumes the font atlas here; egui asserts that it was handled.
            out.textures_delta.clear();
        }
        (seen, cmds)
    }

    fn locked(mut snap: Snapshot) -> Snapshot {
        snap.authed = false;
        if let Some(s) = &mut snap.status {
            s.vault = VaultState::Locked;
        }
        snap
    }

    #[test]
    fn every_screen_renders_and_drawing_alone_sends_nothing() {
        let snap = demo::snapshot();
        for screen in ALL_SCREENS {
            let mut st = UiState {
                screen,
                ..UiState::default()
            };
            let (seen, cmds) = render(&snap, &mut st);
            assert!(seen.contains("Embr"), "{screen:?} drew no top bar");
            assert!(
                cmds.is_empty(),
                "{screen:?} emitted {cmds:?} without any input"
            );
        }
    }

    #[test]
    fn the_screens_show_what_they_are_for() {
        let snap = demo::snapshot();
        for (screen, needle) in [
            (Screen::Dashboard, "waiting for your decision"),
            (Screen::Approvals, "Approve"),
            (Screen::Accounts, "Personal"),
            (Screen::Apps, "OUTKAST"),
            (Screen::Remote, "Enable remote signing"),
            (Screen::Settings, "Change vault password"),
            (Screen::Activity, "allowed by"),
        ] {
            let mut st = UiState {
                screen,
                ..UiState::default()
            };
            let (seen, _) = render(&snap, &mut st);
            assert!(seen.contains(needle), "{screen:?} lacks {needle:?}");
        }
    }

    #[test]
    fn a_locked_vault_shows_nothing_private() {
        let full = demo::snapshot();
        // Collect things that must never be visible without the password.
        let (open, _) = render(&full, &mut UiState::default());
        assert!(
            open.contains("Personal"),
            "sanity: unlocked UI names the account"
        );

        for screen in ALL_SCREENS {
            let mut st = UiState {
                screen,
                ..UiState::default()
            };
            let (seen, cmds) = render(&locked(full.clone()), &mut st);
            for secret in ["Personal", "Work / Bot", "OUTKAST", "npub1", "kind 1"] {
                assert!(
                    !seen.contains(secret),
                    "{screen:?}: locked UI leaks {secret:?}"
                );
            }
            assert!(seen.contains("Vault password"), "no way to unlock");
            assert!(cmds.is_empty());
        }
    }

    #[test]
    fn the_daemon_being_down_is_explained_not_hidden() {
        let snap = Snapshot {
            daemon_down: Some("connection refused".into()),
            ..Snapshot::default()
        };
        let (seen, cmds) = render(&snap, &mut UiState::default());
        assert!(seen.contains("daemon not running"));
        assert!(cmds.is_empty());
    }

    #[test]
    fn locking_wipes_what_was_typed() {
        let mut st = UiState {
            import_secret: "nsec1secret".into(),
            import_password: "hunter2".into(),
            pw_old: "old".into(),
            pw_new: "new".into(),
            export: Some((
                AccountId::from_bytes([1; 16]),
                "vault".into(),
                "export".into(),
            )),
            confirm_remove: Some((AccountId::from_bytes([1; 16]), "Personal".into())),
            password: "typed-to-unlock".into(),
            ..UiState::default()
        };
        render(&locked(demo::snapshot()), &mut st);
        assert!(st.import_secret.is_empty() && st.import_password.is_empty());
        assert!(st.pw_old.is_empty() && st.pw_new.is_empty());
        assert!(st.export.is_none() && st.confirm_remove.is_none());
        assert_eq!(
            st.password, "typed-to-unlock",
            "the unlock field itself stays"
        );
    }

    // ---- what may be remembered ----------------------------------------------------------

    fn lim(sensitive: bool, any_kind: bool, unscoped_decrypt: bool) -> Limits {
        Limits {
            sensitive,
            any_kind,
            unscoped_decrypt,
        }
    }

    #[test]
    fn direct_messages_can_only_be_allowed_once_or_for_the_session() {
        let l = lim(true, false, false);
        let ok: Vec<_> = [
            Duration::Once,
            Duration::Session,
            Duration::Min15,
            Duration::Hour1,
            Duration::Always,
        ]
        .into_iter()
        .filter(|d| duration_allowed(*d, l))
        .collect();
        assert_eq!(ok, [Duration::Once, Duration::Session]);
    }

    #[test]
    fn broad_permissions_are_never_offered_as_permanent() {
        assert!(!duration_allowed(Duration::Always, lim(false, true, false)));
        assert!(!duration_allowed(Duration::Always, lim(false, false, true)));
        assert!(duration_allowed(Duration::Always, lim(false, false, false)));
        assert!(duration_allowed(Duration::Hour1, lim(false, true, true)));
    }

    #[test]
    fn ticking_every_kind_demotes_a_permanent_choice_instead_of_keeping_an_invalid_one() {
        let mut c = Choice {
            duration: Duration::Always,
            any_kind: true,
            account: None,
        };
        clamp_duration(&mut c, lim(false, true, false));
        assert_eq!(c.duration, Duration::Hour1);
        let mut c = Choice {
            duration: Duration::Hour1,
            ..Choice::default()
        };
        clamp_duration(&mut c, lim(true, false, false));
        assert_eq!(c.duration, Duration::Session);
    }

    fn engine_choice(d: DecisionWire) -> PolicyChoice {
        match d {
            DecisionWire::AllowOnce => PolicyChoice::AllowOnce,
            DecisionWire::AllowSession => PolicyChoice::AllowSession,
            DecisionWire::AllowUntil { until } => PolicyChoice::AllowUntil(until),
            DecisionWire::AllowPersistent => PolicyChoice::AllowPersistent,
            other => panic!("the duration buttons never produce {other:?}"),
        }
    }

    /// The property that matters: **every choice the UI offers is one the policy engine accepts**, for
    /// every kind of pending request, so the user never clicks "Approve" and gets an error back.
    #[test]
    fn every_choice_the_ui_offers_is_accepted_by_the_policy_engine() {
        let snap = demo::snapshot();
        let engine = Engine::new();
        let mut checked = 0;
        for view in snap
            .pending
            .iter()
            .filter(|v| v.kind == PendingKind::Operation)
        {
            let op: Operation = view.operation.as_deref().unwrap().parse().unwrap();
            let req = Request {
                client: view.client.pubkey,
                account: view.account.as_ref().unwrap().id,
                op,
                kind: view.event.as_ref().map(|e| e.kind),
                peer: view.peer,
            };
            for any_kind in [false, true] {
                for duration in [
                    Duration::Once,
                    Duration::Session,
                    Duration::Min15,
                    Duration::Hour1,
                    Duration::Always,
                ] {
                    let c = Choice {
                        duration,
                        any_kind: any_kind && view.event.is_some(),
                        account: None,
                    };
                    if !duration_allowed(duration, Limits::of(view, &c)) {
                        continue;
                    }
                    let (decision, scope) = decision_of(view, &c);
                    let scope = scope.map_or_else(
                        || Scope::exact(&req),
                        |s| Scope {
                            kind: s.kind,
                            peer: s.peer,
                            uses: s.uses,
                        },
                    );
                    engine
                        .validate_choice(&req, engine_choice(decision), &scope, now())
                        .unwrap_or_else(|e| {
                            panic!(
                                "UI offered {duration:?} (any_kind={}) for {op:?} kind {:?}: engine says {e}",
                                c.any_kind, req.kind
                            )
                        });
                    checked += 1;
                }
            }
        }
        assert!(
            checked >= 10,
            "the demo should cover several requests ({checked})"
        );
    }

    #[test]
    fn a_one_off_approval_carries_no_scope() {
        let snap = demo::snapshot();
        let view = snap
            .pending
            .iter()
            .find(|v| v.event.is_some())
            .expect("demo has a signing request");
        let (d, scope) = decision_of(view, &Choice::default());
        assert!(matches!(d, DecisionWire::AllowOnce));
        assert!(scope.is_none());
    }

    #[test]
    fn remembering_is_scoped_to_the_kind_and_peer_that_was_asked_about() {
        let snap = demo::snapshot();
        let view = snap
            .pending
            .iter()
            .find(|v| v.event.as_ref().is_some_and(|e| !e.sensitive))
            .expect("demo has a normal signing request");
        let kind = view.event.as_ref().unwrap().kind;
        let (d, scope) = decision_of(
            view,
            &Choice {
                duration: Duration::Hour1,
                ..Choice::default()
            },
        );
        let scope = scope.unwrap();
        assert_eq!(scope.kind, KindScope::Exact(kind));
        assert_eq!(scope.peer, view.peer);
        let DecisionWire::AllowUntil { until } = d else {
            panic!("expected a time-limited allow, got {d:?}");
        };
        let t = now();
        assert!(until > t + 3500 && until <= t + 3601, "{until} vs {t}");
        let (_, wide) = decision_of(
            view,
            &Choice {
                duration: Duration::Hour1,
                any_kind: true,
                account: None,
            },
        );
        assert_eq!(wide.unwrap().kind, KindScope::Any);
    }

    // ---- small helpers -------------------------------------------------------------------

    #[test]
    fn durations_and_ages_are_formatted_for_people() {
        assert_eq!(fmt_ago(5), "5s ago");
        assert_eq!(fmt_ago(300), "5m ago");
        assert_eq!(fmt_ago(7200), "2h ago");
        assert_eq!(fmt_ago(3 * 86_400), "3d ago");
        assert_eq!(fmt_secs(15 * 60), "15 min");
    }

    #[test]
    fn every_audit_outcome_has_words_for_it() {
        use embr_policy::AuditOutcome as O;
        for o in [
            O::AllowedByGrant,
            O::AllowedByUser,
            O::DeniedByGrant,
            O::DeniedByUser,
            O::Refused,
            O::Expired,
            O::Cancelled,
            O::RateLimited,
            O::Paired,
            O::Revoked,
            O::Admin,
        ] {
            let (text, _) = outcome_label(o);
            assert!(!text.is_empty() && !text.contains('_') && text == text.to_lowercase());
        }
    }
}
