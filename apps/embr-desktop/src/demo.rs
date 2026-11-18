//! `embr --demo [screen]`: the UI with canned data and **no connection to any daemon**. For screenshots,
//! documentation and visual checks. Nothing here touches keys or the network.

use embr_core::{AccountId, AccountMeta, KeySecurity, Pubkey32};
use embr_ipc::control::{
    ClientIdent, ClientView, EventPreview, Nip46Status, PeerHint, PendingKind, PendingView,
    RelayView, Settings, SignerView, StatusView, VaultState,
};
use embr_policy::{
    AuditOutcome, AuditRecord, ClientRecord, Effect, Expiry, Grant, GrantId, KindScope,
};

use crate::backend::{Notice, Snapshot};

fn key(n: u8) -> Pubkey32 {
    Pubkey32::from_bytes([n; 32])
}

fn account(n: u8, label: &str, sec: KeySecurity) -> AccountMeta {
    AccountMeta {
        id: AccountId::from_bytes([n; 16]),
        label: label.into(),
        pubkey_hex: hex(&[n; 32]),
        npub: format!("npub1{}", "q".repeat(8) + &"x".repeat(50)),
        created_at: 1_700_000_000,
        key_security: sec,
        has_avatar: false,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A snapshot that exercises every screen, including hostile-looking text (already sanitised the way
/// the daemon does it).
pub fn snapshot() -> Snapshot {
    let main = account(1, "Personal", KeySecurity::Medium);
    let work = account(2, "Work / Bot", KeySecurity::Weak);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let client = |n: u8, name: &str, via: &str, pid: Option<i32>| ClientIdent {
        pubkey: key(n),
        name: name.into(),
        peer: pid.map(|p| PeerHint {
            pid: Some(p),
            uid: 1000,
            exe: Some("/usr/bin/outkast".into()),
        }),
        via: via.into(),
    };
    let blank = |id: u64, kind: PendingKind, who: ClientIdent| PendingView {
        id,
        digest: "00".repeat(32),
        kind,
        client: who,
        account: Some(main.clone()),
        operation: None,
        legacy: false,
        reveals_plaintext: false,
        event: None,
        peer: None,
        text_preview: None,
        payload_len: None,
        requested_permissions: Vec::new(),
        created_at: now,
        expires_at: now + 112,
    };
    let mut pair = blank(
        1,
        PendingKind::Pair,
        client(3, "OUTKAST", "local", Some(4242)),
    );
    pair.requested_permissions = vec!["sign_event:1".into(), "nip44_encrypt".into()];
    let mut sign = blank(
        2,
        PendingKind::Operation,
        client(3, "OUTKAST", "local", Some(4242)),
    );
    sign.operation = Some("sign_event".into());
    sign.event = Some(EventPreview {
        kind: 1,
        content: "pay here ⟦U+202E⟧gnp.exe — hello nostr 🔥 日本語\n↵ second line".into(),
        content_len: 61,
        tags: vec![
            vec!["t".into(), "nostr".into()],
            vec!["p".into(), "3bf0c63f…aefa459d".into()],
        ],
        tags_total: 2,
        created_at: None,
        sensitive: false,
    });
    let mut dm = blank(
        3,
        PendingKind::Operation,
        client(5, "Web client", "nip46", None),
    );
    dm.operation = Some("sign_event".into());
    dm.event = Some(EventPreview {
        kind: 14,
        content: "a private chat message".into(),
        content_len: 22,
        tags: vec![vec!["p".into(), "abcdef…".into()]],
        tags_total: 1,
        created_at: None,
        sensitive: true,
    });
    let mut dec = blank(
        4,
        PendingKind::Operation,
        client(3, "OUTKAST", "local", Some(4242)),
    );
    dec.operation = Some("nip04_decrypt".into());
    dec.legacy = true;
    dec.reveals_plaintext = true;
    dec.peer = Some(key(9));
    dec.payload_len = Some(180);

    let record = |n: u8, name: &str, via: &str, acct: &AccountMeta| ClientRecord {
        key: key(n),
        name: name.into(),
        accounts: vec![acct.id],
        created_at: now - 86_400,
        last_seen: now - 60,
        via: via.into(),
    };
    let grant = |id: u64,
                 n: u8,
                 acct: &AccountMeta,
                 op: embr_core::Operation,
                 kind: KindScope,
                 effect: Effect,
                 expiry: Expiry| Grant {
        id: GrantId(id),
        client: key(n),
        account: acct.id,
        op,
        kind,
        peer: None,
        effect,
        expiry,
        uses_left: None,
        created_at: now - 3600,
    };
    let log = |ago: u64,
               via: &str,
               action: &str,
               kind: Option<u16>,
               name: &str,
               outcome: AuditOutcome| AuditRecord {
        ts: now - ago,
        via: via.into(),
        client: Some(key(3)),
        client_name: Some(name.into()),
        account: Some(main.id),
        action: action.into(),
        kind,
        outcome,
        grant: None,
        note: None,
    };
    Snapshot {
        daemon_down: None,
        status: Some(StatusView { version: env!("CARGO_PKG_VERSION").into(), vault: VaultState::Unlocked, pending: 4, lock_timeout_secs: 900, locks_in_secs: Some(742), remote_signing_enabled: true }),
        authed: true,
        accounts: vec![main.clone(), work.clone()],
        active: Some(main.id),
        pending: vec![pair, sign, dm, dec],
        clients: vec![
            ClientView { record: record(3, "OUTKAST", "local", &main), grants: 2, connected: 1 },
            ClientView { record: record(5, "Web client", "nip46", &work), grants: 0, connected: 0 },
        ],
        grants: vec![
            grant(1, 3, &main, embr_core::Operation::SignEvent, KindScope::Exact(1), Effect::Allow, Expiry::Never),
            grant(2, 3, &main, embr_core::Operation::SignEvent, KindScope::Exact(7), Effect::Allow, Expiry::Until(now + 3300)),
        ],
        settings: Some(Settings { lock_timeout_secs: 900, notifications: true, remote_signing_enabled: true, relays: vec!["wss://relay.example.com/".into(), "ws://localhost:7777/".into()] }),
        nip46: Some(Nip46Status {
            enabled: true,
            running: true,
            relays: vec![
                RelayView { url: "wss://relay.example.com/".into(), state: "connected".into(), detail: None },
                RelayView { url: "ws://localhost:7777/".into(), state: "failed".into(), detail: Some("connection refused".into()) },
            ],
            signers: vec![SignerView { account: main.id, transport_pubkey: key(7) }],
        }),
        log: vec![
            log(3000, "local", "pair", None, "OUTKAST", AuditOutcome::Paired),
            log(1200, "local", "sign_event", Some(1), "OUTKAST", AuditOutcome::AllowedByUser),
            log(300, "nip46", "sign_event", Some(14), "Web client", AuditOutcome::DeniedByUser),
            log(40, "local", "sign_event", Some(1), "OUTKAST", AuditOutcome::AllowedByGrant),
        ],
        notice: Some(Notice { text: "Settings saved.".into(), error: false, seq: 1 }),
        bunker_uri: Some("bunker://0707070707070707070707070707070707070707070707070707070707070707?relay=wss%3A%2F%2Frelay.example.com%2F&secret=0123456789abcdef0123456789abcdef".into()),
        exported: None,
    }
}
