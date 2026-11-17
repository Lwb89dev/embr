//! `embrctl` — command-line control of the Embr signer.
//!
//! Passwords are read from a no-echo prompt (or from stdin with `--password-stdin`), **never from
//! arguments or the environment**, so they cannot leak through `ps`, shell history or `/proc`.
// `serde_json::Value["field"]` never panics (a missing field yields `Null`), so the indexing lint
// is a false positive for the JSON access in this file.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::indexing_slicing)]

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use embr_client::ClientError;
use embr_client::control::ControlClient;
use embr_core::{AccountId, AccountMeta};
use embr_ipc::control::{
    ClientView, ControlEvent, DecisionWire, PendingKind, PendingView, VaultState,
};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(name = "embrctl", version, about = "Control the Embr signer (embrd)")]
struct Cli {
    /// Control socket (default: the per-user control socket).
    #[arg(long, global = true, value_name = "PATH")]
    control_socket: Option<PathBuf>,
    /// Read the vault password from the first line of stdin instead of prompting.
    #[arg(long, global = true)]
    password_stdin: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show daemon status (no password needed).
    Status,
    /// Create the vault.
    Init,
    /// Unlock the vault (it stays unlocked in the daemon).
    Unlock,
    /// Lock the vault now (wipes keys from memory).
    Lock,
    /// Manage accounts.
    Accounts {
        #[command(subcommand)]
        cmd: Option<AccountCmd>,
    },
    /// List pending approval requests.
    Pending,
    /// Answer approval requests interactively (a terminal approval UI).
    Watch {
        /// Exit after answering this many requests (useful for scripts).
        #[arg(long)]
        max: Option<usize>,
    },
    /// List paired applications.
    Clients,
    /// List stored permissions.
    Grants,
    /// Forget a paired application (it must be approved again).
    Revoke { key: String },
    /// Block an application's key permanently.
    Block { key: String },
    /// Remove one stored permission.
    RevokeGrant { id: u64 },
    /// Show the recent activity log (metadata only).
    Log {
        #[arg(default_value_t = 20)]
        n: usize,
    },
    /// Write an encrypted backup of the vault (absolute path; must not exist).
    Backup { path: PathBuf },
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Generate a new identity inside the vault.
    Add { label: String },
    /// Import an `nsec`/hex key (read from the prompt or stdin, never argv).
    Import { label: String },
    /// Import a NIP-49 `ncryptsec` backup.
    ImportNcryptsec { label: String },
    /// Switch the active account.
    Use { id: String },
    /// Rename an account.
    Rename { id: String, label: String },
    /// Delete an account **and its key**.
    Remove { id: String },
    /// Export an account as a NIP-49 `ncryptsec`.
    Export { id: String },
    /// Show an account's private key (asks for the vault password again).
    Reveal { id: String },
}

type Res<T> = Result<T, String>;

fn e(err: ClientError) -> String {
    match err {
        ClientError::Connect(io) => {
            format!("cannot reach the signer daemon ({io}). Is `embrd` running?")
        }
        ClientError::Rpc(r) => format!("{} ({})", r.message, r.name),
        other => other.to_string(),
    }
}

fn prompt_secret(prompt: &str, from_stdin: bool) -> Res<String> {
    if from_stdin || !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|x| x.to_string())?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_owned());
    }
    rpassword::prompt_password(prompt).map_err(|x| x.to_string())
}

fn line_from_stdin(prompt: &str) -> Res<String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|x| x.to_string())?;
    Ok(line.trim().to_owned())
}

struct Session {
    c: ControlClient,
    password: Option<String>,
}

fn connect(cli: &Cli) -> Res<ControlClient> {
    ControlClient::connect(cli.control_socket.clone()).map_err(e)
}

fn authed(cli: &Cli) -> Res<Session> {
    let mut c = connect(cli)?;
    match c.hello.status.vault {
        VaultState::Missing => return Err("no vault yet: run `embrctl init`".into()),
        VaultState::Locked | VaultState::Unlocked => {}
    }
    let pw = prompt_secret("Vault password: ", cli.password_stdin)?;
    c.unlock(&pw).map_err(e)?;
    Ok(Session {
        c,
        password: Some(pw),
    })
}

fn accounts_of(c: &mut ControlClient) -> Res<(Vec<AccountMeta>, Option<AccountId>)> {
    let v = c.call("list_accounts", json!({})).map_err(e)?;
    let accounts: Vec<AccountMeta> =
        serde_json::from_value(v["accounts"].clone()).map_err(|x| x.to_string())?;
    let active = serde_json::from_value(v["active"].clone()).ok();
    Ok((accounts, active))
}

/// Accepts a full id, or any unambiguous prefix of an id or label.
fn resolve_account(c: &mut ControlClient, what: &str) -> Res<AccountMeta> {
    let (accounts, _) = accounts_of(c)?;
    let hits: Vec<&AccountMeta> = accounts
        .iter()
        .filter(|a| {
            a.id.to_string().starts_with(what) || a.label == what || a.pubkey_hex.starts_with(what)
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!("no account matches {what:?}")),
        _ => Err(format!(
            "{what:?} is ambiguous; use more characters of the id"
        )),
    }
}

fn print_accounts(accounts: &[AccountMeta], active: Option<AccountId>) {
    if accounts.is_empty() {
        println!("(no accounts — add one with `embrctl accounts add <label>`)");
    }
    for a in accounts {
        println!(
            "{} {}  {}  {}  [{:?}]",
            if Some(a.id) == active { "*" } else { " " },
            a.id,
            a.label,
            a.npub,
            a.key_security
        );
    }
}

fn run(cli: Cli) -> Res<()> {
    match &cli.cmd {
        Cmd::Status => {
            let mut c = connect(&cli)?;
            let s = c.status().map_err(e)?;
            println!("embrd {}", s.version);
            println!("vault:              {:?}", s.vault);
            println!("pending requests:   {}", s.pending);
            println!(
                "auto-lock:          {}",
                if s.lock_timeout_secs == 0 {
                    "never".into()
                } else {
                    format!("after {} s idle", s.lock_timeout_secs)
                }
            );
            if let Some(n) = s.locks_in_secs {
                println!("locks in:           {n} s");
            }
            println!(
                "remote signing:     {}",
                if s.remote_signing_enabled {
                    "ON"
                } else {
                    "off"
                }
            );
        }
        Cmd::Init => {
            let mut c = connect(&cli)?;
            if c.hello.status.vault != VaultState::Missing {
                return Err("a vault already exists".into());
            }
            let p1 = prompt_secret(
                "Choose a vault password (min. 10 characters): ",
                cli.password_stdin,
            )?;
            if !cli.password_stdin && std::io::stdin().is_terminal() {
                let p2 = prompt_secret("Repeat it: ", false)?;
                if p1 != p2 {
                    return Err("the passwords do not match".into());
                }
            }
            c.create_vault(&p1).map_err(e)?;
            println!(
                "Vault created and unlocked. Add an identity: `embrctl accounts add <label>`."
            );
            println!(
                "There is NO way to recover a forgotten password: keep a NIP-49 export (`accounts export`) of your keys."
            );
        }
        Cmd::Unlock => {
            authed(&cli)?;
            println!("Unlocked.");
        }
        Cmd::Lock => {
            let mut s = authed(&cli)?;
            s.c.call("lock", json!({})).map_err(e)?;
            println!("Locked.");
        }
        Cmd::Accounts { cmd } => {
            let mut s = authed(&cli)?;
            match cmd {
                None => {
                    let (accounts, active) = accounts_of(&mut s.c)?;
                    print_accounts(&accounts, active);
                }
                Some(AccountCmd::Add { label }) => {
                    let v =
                        s.c.call("add_generated", json!({"label": label}))
                            .map_err(e)?;
                    println!("Created {} ({})", v["npub"], v["id"]);
                }
                Some(AccountCmd::Import { label }) => {
                    let secret =
                        prompt_secret("Private key (nsec1… or hex): ", cli.password_stdin)?;
                    let v =
                        s.c.call("import_secret", json!({"label": label, "secret": secret}))
                            .map_err(e)?;
                    println!(
                        "Imported {} ({}). It is recorded as handled insecurely (pasted).",
                        v["npub"], v["id"]
                    );
                }
                Some(AccountCmd::ImportNcryptsec { label }) => {
                    let enc = prompt_secret("ncryptsec1…: ", cli.password_stdin)?;
                    let pw = prompt_secret("Its password: ", cli.password_stdin)?;
                    let v =
                        s.c.call(
                            "import_ncryptsec",
                            json!({"label": label, "ncryptsec": enc, "password": pw}),
                        )
                        .map_err(e)?;
                    println!("Imported {} ({})", v["npub"], v["id"]);
                }
                Some(AccountCmd::Use { id }) => {
                    let a = resolve_account(&mut s.c, id)?;
                    s.c.call("set_active", json!({"id": a.id.to_string()}))
                        .map_err(e)?;
                    println!("Active account: {} ({})", a.label, a.npub);
                }
                Some(AccountCmd::Rename { id, label }) => {
                    let a = resolve_account(&mut s.c, id)?;
                    s.c.call("set_label", json!({"id": a.id.to_string(), "label": label}))
                        .map_err(e)?;
                }
                Some(AccountCmd::Remove { id }) => {
                    let a = resolve_account(&mut s.c, id)?;
                    println!(
                        "This permanently deletes the key of {} ({}).",
                        a.label, a.npub
                    );
                    println!(
                        "Make sure you have a NIP-49 export (`embrctl accounts export`) if you may need it again."
                    );
                    if line_from_stdin(&format!("Type the label ({}) to confirm: ", a.label))?
                        != a.label
                    {
                        return Err("not confirmed; nothing was removed".into());
                    }
                    s.c.call(
                        "remove_account",
                        json!({"id": a.id.to_string(), "confirm": true}),
                    )
                    .map_err(e)?;
                    println!("Removed.");
                }
                Some(AccountCmd::Export { id }) => {
                    let a = resolve_account(&mut s.c, id)?;
                    let export_pw =
                        prompt_secret("Password to protect the export: ", cli.password_stdin)?;
                    let vault_pw = s.password.clone().unwrap_or_default();
                    let v = s.c.call("export_ncryptsec", json!({"id": a.id.to_string(), "vault_password": vault_pw, "export_password": export_pw, "log_n": 18})).map_err(e)?;
                    println!("{}", v["ncryptsec"].as_str().unwrap_or_default());
                }
                Some(AccountCmd::Reveal { id }) => {
                    let a = resolve_account(&mut s.c, id)?;
                    eprintln!(
                        "WARNING: this prints the private key of {}. Anyone who sees it controls that identity forever.",
                        a.label
                    );
                    if line_from_stdin("Type REVEAL to continue: ")? != "REVEAL" {
                        return Err("not confirmed".into());
                    }
                    let vault_pw = s.password.clone().unwrap_or_default();
                    let v =
                        s.c.call(
                            "reveal_nsec",
                            json!({"id": a.id.to_string(), "vault_password": vault_pw}),
                        )
                        .map_err(e)?;
                    println!("{}", v["nsec"].as_str().unwrap_or_default());
                }
            }
        }
        Cmd::Pending => {
            let mut s = authed(&cli)?;
            let p = s.c.pending().map_err(e)?;
            if p.is_empty() {
                println!("(nothing pending)");
            }
            for v in &p {
                describe(v);
            }
        }
        Cmd::Watch { max } => watch(&cli, *max)?,
        Cmd::Clients => {
            let mut s = authed(&cli)?;
            let v = s.c.call("list_clients", json!({})).map_err(e)?;
            let clients: Vec<ClientView> = serde_json::from_value(v).map_err(|x| x.to_string())?;
            if clients.is_empty() {
                println!("(no paired applications)");
            }
            for c in clients {
                println!(
                    "{}  \"{}\" (unverified name)  accounts={}  grants={}  connected={}",
                    c.record.key,
                    c.record.name,
                    c.record.accounts.len(),
                    c.grants,
                    c.connected
                );
            }
        }
        Cmd::Grants => {
            let mut s = authed(&cli)?;
            let v = s.c.call("list_grants", json!({})).map_err(e)?;
            let grants: Vec<embr_policy::Grant> =
                serde_json::from_value(v).map_err(|x| x.to_string())?;
            if grants.is_empty() {
                println!("(no stored permissions)");
            }
            for g in grants {
                println!(
                    "#{:<4} {:?} {} kind={:?} peer={} client={} expiry={:?} uses_left={:?}",
                    g.id.0,
                    g.effect,
                    g.op,
                    g.kind,
                    g.peer.map_or("any".into(), |p| p.short()),
                    g.client.short(),
                    g.expiry,
                    g.uses_left
                );
            }
        }
        Cmd::Revoke { key } => {
            let mut s = authed(&cli)?;
            s.c.call("revoke_client", json!({"key": key})).map_err(e)?;
            println!("Revoked.");
        }
        Cmd::Block { key } => {
            let mut s = authed(&cli)?;
            s.c.call("block_client", json!({"key": key})).map_err(e)?;
            println!("Blocked.");
        }
        Cmd::RevokeGrant { id } => {
            let mut s = authed(&cli)?;
            let v = s.c.call("revoke_grant", json!({"id": id})).map_err(e)?;
            println!(
                "{}",
                if v == Value::Bool(true) {
                    "Revoked."
                } else {
                    "No such permission."
                }
            );
        }
        Cmd::Log { n } => {
            let mut s = authed(&cli)?;
            let v = s.c.call("recent_log", json!({"limit": n})).map_err(e)?;
            for r in v.as_array().cloned().unwrap_or_default() {
                println!(
                    "{} {:<7} {:<16} kind={} {:<16} client={} {}",
                    r["ts"],
                    r["via"].as_str().unwrap_or(""),
                    r["action"].as_str().unwrap_or(""),
                    r["kind"],
                    r["outcome"].as_str().unwrap_or(""),
                    r["client"]
                        .as_str()
                        .map_or("-".into(), |k| format!("{}…", k.get(..8).unwrap_or(k))),
                    r["note"].as_str().unwrap_or("")
                );
            }
        }
        Cmd::Backup { path } => {
            let mut s = authed(&cli)?;
            s.c.call("export_backup", json!({"dest": path.display().to_string()}))
                .map_err(e)?;
            println!(
                "Encrypted backup written to {}. It is protected by your CURRENT vault password.",
                path.display()
            );
        }
    }
    Ok(())
}

fn describe(v: &PendingView) {
    println!("────────────────────────────────────────────────────────────");
    println!(
        "Request #{}  from \"{}\"  (name is UNVERIFIED)",
        v.id, v.client.name
    );
    println!("  client key : {}", v.client.pubkey);
    if let Some(p) = &v.client.peer {
        println!(
            "  process    : pid={:?} exe={} (hints only — can be spoofed)",
            p.pid,
            p.exe.as_deref().unwrap_or("?")
        );
    }
    match v.kind {
        PendingKind::Pair => {
            println!("  wants to PAIR with this signer.");
            if !v.requested_permissions.is_empty() {
                println!("  it asks for: {}", v.requested_permissions.join(", "));
            }
        }
        PendingKind::Operation => {
            if let Some(a) = &v.account {
                println!("  account    : {} ({})", a.label, a.npub);
            }
            println!(
                "  operation  : {}{}",
                v.operation.as_deref().unwrap_or("?"),
                if v.legacy { "  [LEGACY NIP-04]" } else { "" }
            );
            if v.reveals_plaintext {
                println!("  ⚠ this returns the PLAINTEXT of a private message to the application");
            }
            if let Some(p) = v.peer {
                println!("  peer       : {p}");
            }
            if let Some(ev) = &v.event {
                println!(
                    "  event kind : {}{}",
                    ev.kind,
                    if ev.sensitive {
                        "  ⚠ direct-message kind"
                    } else {
                        ""
                    }
                );
                println!("  content    : {} ({} bytes)", ev.content, ev.content_len);
                for t in &ev.tags {
                    println!("  tag        : {}", t.join(" | "));
                }
                if ev.tags_total > ev.tags.len() {
                    println!("  … {} more tags", ev.tags_total - ev.tags.len());
                }
            }
            if let Some(t) = &v.text_preview {
                println!("  plaintext  : {t}");
            }
            if let Some(n) = v.payload_len {
                println!("  payload    : {n} bytes");
            }
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Asks the user about one request. Returns `Ok(true)` if it was answered.
fn answer(c: &mut ControlClient, v: &PendingView) -> Res<bool> {
    describe(v);
    let decision = loop {
        let choice = match v.kind {
            PendingKind::Pair => line_from_stdin(
                "  [a]pprove (active account)  [r]eject  [b]lock this app  [i]gnore > ",
            )?,
            PendingKind::Operation => line_from_stdin(
                "  [o]nce  [s]ession  [t] 15 min  [p]ersistent  [n]o once  [N] always no  [b]lock  [i]gnore > ",
            )?,
        };
        let d = match (v.kind, choice.as_str()) {
            (_, "i" | "") => return Ok(false),
            (_, "b") => DecisionWire::BlockClient,
            (PendingKind::Pair, "a") => {
                let (_, active) = accounts_of(c)?;
                let acct = active.ok_or("there is no active account; add one first")?;
                DecisionWire::Pair { account: acct }
            }
            (PendingKind::Pair, "r") => DecisionWire::RejectOnce,
            (PendingKind::Operation, "o") => DecisionWire::AllowOnce,
            (PendingKind::Operation, "s") => DecisionWire::AllowSession,
            (PendingKind::Operation, "t") => DecisionWire::AllowUntil { until: now() + 900 },
            (PendingKind::Operation, "p") => DecisionWire::AllowPersistent,
            (PendingKind::Operation, "n") => DecisionWire::RejectOnce,
            (PendingKind::Operation, "N") => DecisionWire::AlwaysReject,
            _ => {
                println!("  (unrecognised)");
                continue;
            }
        };
        match c.decide(v, d, None) {
            Ok(_) => break d,
            // e.g. "too broad": the request stays pending, let the user choose again.
            Err(err) => println!("  refused: {}", e(err)),
        }
    };
    println!("  → {decision:?}");
    Ok(true)
}

fn watch(cli: &Cli, max: Option<usize>) -> Res<()> {
    let mut s = authed(cli)?;
    s.c.subscribe().map_err(e)?;
    println!("Watching for approval requests (Ctrl-C to stop)…");
    let mut answered = 0usize;
    let mut seen: Vec<u64> = Vec::new();
    loop {
        for v in s.c.pending().map_err(e)? {
            if seen.contains(&v.id) {
                continue;
            }
            seen.push(v.id);
            if answer(&mut s.c, &v)? {
                answered += 1;
                if max.is_some_and(|m| answered >= m) {
                    return Ok(());
                }
            }
        }
        match s.c.next_event().map_err(e)? {
            Some(ControlEvent::Locked) => return Err("the vault was locked".into()),
            Some(ControlEvent::PendingAdded { request }) => {
                if !seen.contains(&request.id) {
                    seen.push(request.id);
                    if answer(&mut s.c, &request)? {
                        answered += 1;
                        if max.is_some_and(|m| answered >= m) {
                            return Ok(());
                        }
                    }
                }
            }
            Some(ControlEvent::PendingRemoved { id, reason }) => {
                println!("(request #{id} {reason})")
            }
            _ => {}
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("embrctl: {msg}");
            ExitCode::FAILURE
        }
    }
}
