//! Interoperability with an independent implementation (nostr-tools, JavaScript).
//!
//! * `accepts_nostr_tools_artefacts` – Embr verifies/decrypts/imports what nostr-tools produced
//!   (`tests/vectors/interop_nostr_tools.json`, regenerate with `tests/interop/gen_vectors.mjs`).
//! * `emit_for_nostr_tools` – Embr produces artefacts into `target/interop/rust_out.json`, which
//!   `tests/interop/verify_rust.mjs` then checks with nostr-tools (see `tests/interop/run.sh`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{hex32, load_json};
use embr_core::KeySecurity;
use embr_crypto::{EventTemplate, Identity, Limits, parse_public_key};
use nostr::event::Event;
use serde_json::{Value, json};

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("missing string field {k}"))
}

#[test]
fn accepts_nostr_tools_artefacts() {
    let v = load_json("interop_nostr_tools.json");
    let limits = Limits::default();
    assert_eq!(v["generator"]["name"], "nostr-tools");

    // Events signed by nostr-tools verify in Embr, and the author key derivation agrees.
    for e in v["events"].as_array().unwrap() {
        let ev: Event = serde_json::from_value(e["event"].clone()).unwrap();
        ev.verify()
            .unwrap_or_else(|err| panic!("kind {} failed to verify: {err}", ev.kind.as_u16()));
        let id = Identity::from_secret_bytes(&hex32(s(e, "secret_hex"))).unwrap();
        assert_eq!(ev.pubkey, id.public_key());
    }

    // Same event ids when Embr signs the same template (id derivation is independent of the
    // signature): re-sign each nostr-tools event's template and compare ids.
    for e in v["events"].as_array().unwrap() {
        let id = Identity::from_secret_bytes(&hex32(s(e, "secret_hex"))).unwrap();
        let src = &e["event"];
        let tpl = EventTemplate {
            kind: src["kind"].as_u64().unwrap() as u16,
            content: s(src, "content").to_string(),
            tags: serde_json::from_value(src["tags"].clone()).unwrap(),
            created_at: src["created_at"].as_u64(),
            pubkey: None,
            id: Some(s(src, "id").to_string()), // Embr verifies this against its own computation
        };
        let ours = id.sign_event(&tpl, &limits).unwrap();
        assert_eq!(ours.id.to_hex(), s(src, "id"));
    }

    // The ambiguous-control-character event: refused by default, same id when explicitly allowed.
    let amb = &v["ambiguous_control"];
    let id = Identity::from_secret_bytes(&hex32(s(amb, "secret_hex"))).unwrap();
    let src = &amb["event"];
    let tpl = EventTemplate {
        kind: 1,
        content: s(src, "content").to_string(),
        tags: vec![],
        created_at: src["created_at"].as_u64(),
        pubkey: None,
        id: Some(s(src, "id").to_string()),
    };
    assert!(id.sign_event(&tpl, &limits).is_err());
    let permissive = Limits {
        allow_ambiguous_control_chars: true,
        ..Limits::default()
    };
    assert_eq!(
        id.sign_event(&tpl, &permissive).unwrap().id.to_hex(),
        s(src, "id")
    );
    // ...and a verifier-side Embr can still verify the foreign event.
    let foreign: Event = serde_json::from_value(src.clone()).unwrap();
    foreign.verify().unwrap();

    // NIP-44 payloads from nostr-tools decrypt in Embr.
    for p in v["nip44"].as_array().unwrap() {
        let recipient_pk = parse_public_key(s(p, "recipient_pubkey_hex")).unwrap();
        let sender = Identity::from_secret_bytes(&hex32(s(p, "sender_secret_hex"))).unwrap();
        // Decrypt as the *recipient* would need the recipient's secret; we have the sender's, and
        // ECDH is symmetric, so decrypting "from the recipient" with the sender key is equivalent.
        let pt = sender
            .nip44_decrypt(&recipient_pk, s(p, "payload"), &limits)
            .unwrap();
        assert_eq!(&*pt, s(p, "plaintext"));
    }

    // NIP-04 payloads.
    for p in v["nip04"].as_array().unwrap() {
        let recipient_pk = parse_public_key(s(p, "recipient_pubkey_hex")).unwrap();
        let sender = Identity::from_secret_bytes(&hex32(s(p, "sender_secret_hex"))).unwrap();
        let pt = sender
            .nip04_decrypt(&recipient_pk, s(p, "payload"), &limits)
            .unwrap();
        assert_eq!(&*pt, s(p, "plaintext"));
    }

    // ncryptsec from nostr-tools imports, with the right key-security byte.
    for p in v["nip49"].as_array().unwrap() {
        let (id, sec) =
            Identity::from_ncryptsec(s(p, "ncryptsec"), s(p, "password"), &limits).unwrap();
        assert_eq!(hex::encode(*id.secret_bytes()), s(p, "secret_hex"));
        let expected = match p["key_security_byte"].as_u64().unwrap() {
            0 => KeySecurity::Weak,
            1 => KeySecurity::Medium,
            _ => KeySecurity::Unknown,
        };
        assert_eq!(sec, expected);
    }

    // NIP-19.
    for p in v["nip19"].as_array().unwrap() {
        let id = Identity::from_secret_str(s(p, "nsec")).unwrap();
        assert_eq!(hex::encode(*id.secret_bytes()), s(p, "secret_hex"));
        assert_eq!(id.pubkey_hex(), s(p, "pubkey_hex"));
        assert_eq!(id.npub(), s(p, "npub"));
        assert_eq!(&**id.reveal_nsec().unwrap(), s(p, "nsec"));
    }
}

#[test]
fn emit_for_nostr_tools() {
    let limits = Limits::default();
    let alice = Identity::generate();
    let bob = Identity::generate();

    let contents = [
        "hello",
        "",
        "q\" b\\ nl\n tab\t",
        "日本語 🔥 \u{202e}",
        &"x".repeat(10_000),
    ];
    let mut events = vec![];
    for (i, content) in contents.iter().enumerate() {
        let t = EventTemplate {
            kind: [1u16, 4, 7, 24133, 30023][i],
            content: (*content).to_string(),
            tags: vec![
                vec!["e".into(), "b".repeat(64)],
                vec!["alt".into(), "a \"b\" \\ \n".into()],
            ],
            created_at: Some(1_700_000_000 + i as u64),
            pubkey: None,
            id: None,
        };
        events.push(serde_json::to_value(alice.sign_event(&t, &limits).unwrap()).unwrap());
    }

    let mut nip44 = vec![];
    let mut nip04 = vec![];
    for pt in [
        "a",
        "hello",
        "日本語 🔥",
        &"z".repeat(1000),
        &"y".repeat(65_535),
    ] {
        nip44.push(json!({
            "sender_pubkey_hex": alice.pubkey_hex(),
            "recipient_secret_hex": hex::encode(*bob.secret_bytes()),
            "plaintext": pt,
            "payload": alice.nip44_encrypt(&bob.public_key(), pt, &limits).unwrap(),
        }));
    }
    for pt in ["legacy", "日本語 🔥", &"w".repeat(2000)] {
        nip04.push(json!({
            "sender_pubkey_hex": alice.pubkey_hex(),
            "recipient_secret_hex": hex::encode(*bob.secret_bytes()),
            "plaintext": pt,
            "payload": alice.nip04_encrypt(&bob.public_key(), pt, &limits).unwrap(),
        }));
    }

    let mut nip49 = vec![];
    for password in ["nostr", "p\u{e4}ssw\u{f6}rd \u{212b}\u{2126}"] {
        nip49.push(json!({
            "secret_hex": hex::encode(*alice.secret_bytes()),
            "password": password,
            "ncryptsec": alice.export_ncryptsec(password, 16, KeySecurity::Medium).unwrap(),
        }));
    }

    let nip19 = vec![json!({
        "secret_hex": hex::encode(*alice.secret_bytes()),
        "nsec": &**alice.reveal_nsec().unwrap(),
        "pubkey_hex": alice.pubkey_hex(),
        "npub": alice.npub(),
    })];

    let out =
        json!({ "events": events, "nip44": nip44, "nip04": nip04, "nip49": nip49, "nip19": nip19 });
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/interop");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("rust_out.json"),
        serde_json::to_string_pretty(&out).unwrap(),
    )
    .unwrap();
}
