//! NIP-01 event signing: id derivation checked against an independent implementation of the
//! spec's serialization rules, signature verification, and the signer-specific guarantees
//! (no pubkey substitution, no trusted `id`/`sig`, strict templates, limits).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use embr_crypto::{CryptoError, EventTemplate, Identity, Limits};
use sha2::{Digest, Sha256};

/// Independent NIP-01 serializer: escapes exactly the characters the spec lists, everything else
/// verbatim (note: this differs from `serde_json`, which also escapes other control characters).
fn nip01_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn nip01_id(
    pubkey: &str,
    created_at: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    let tags_json = tags
        .iter()
        .map(|t| {
            format!(
                "[{}]",
                t.iter()
                    .map(|x| nip01_string(x))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let ser = format!(
        "[0,\"{pubkey}\",{created_at},{kind},[{tags_json}],{}]",
        nip01_string(content)
    );
    hex::encode(Sha256::digest(ser.as_bytes()))
}

fn tpl(kind: u16, content: &str) -> EventTemplate {
    EventTemplate {
        kind,
        content: content.into(),
        tags: vec![],
        created_at: Some(1_700_000_000),
        pubkey: None,
        id: None,
    }
}

#[test]
fn signed_event_verifies_and_has_spec_id() {
    let id = Identity::generate();
    let limits = Limits::default();
    let contents = [
        "hello nostr",
        "",
        "quote \" backslash \\ newline \n cr \r tab \t",
        "bs \u{08} ff \u{0c} del \u{7f}",
        "unicode: 日本語 🔥 ünïcödé \u{202e}rtl-override",
    ];
    let tags = vec![
        vec![
            "e".to_string(),
            "a".repeat(64),
            "wss://relay.example".to_string(),
        ],
        vec![
            "alt".to_string(),
            "with \"quotes\" and \\ and \n".to_string(),
        ],
        vec!["t".to_string()],
    ];
    for content in contents {
        for kind in [0u16, 1, 4, 7, 14, 1059, 10002, 24133, 30023, 65535] {
            let mut t = tpl(kind, content);
            t.tags = tags.clone();
            let ev = id.sign_event(&t, &limits).unwrap();

            assert_eq!(ev.pubkey, id.public_key());
            assert_eq!(ev.kind.as_u16(), kind);
            assert_eq!(ev.content, content);
            assert_eq!(ev.created_at.as_secs(), 1_700_000_000);
            ev.verify().unwrap();
            assert_eq!(
                ev.id.to_hex(),
                nip01_id(&id.pubkey_hex(), 1_700_000_000, kind, &tags, content),
                "id must follow NIP-01 serialization (kind {kind}, content {content:?})"
            );
        }
    }
}

/// Finding documented in docs/RESEARCH.md: NIP-01's literal text ("all other characters verbatim")
/// and every JSON-library-based implementation disagree about C0 control characters, so the id
/// depends on the verifier. Embr refuses by default and, when explicitly allowed, follows the
/// JSON-library behaviour shared by nostr-tools and rust-nostr.
#[test]
fn ambiguous_control_characters_are_refused_by_default() {
    let id = Identity::generate();
    for c in ['\u{00}', '\u{01}', '\u{07}', '\u{0b}', '\u{0e}', '\u{1f}'] {
        let t = tpl(1, &format!("a{c}b"));
        assert!(
            matches!(
                id.sign_event(&t, &Limits::default()),
                Err(CryptoError::InvalidEvent(_))
            ),
            "U+{:04X} in content must be refused",
            c as u32
        );
        let mut t = tpl(1, "ok");
        t.tags = vec![vec!["t".into(), format!("x{c}")]];
        assert!(
            id.sign_event(&t, &Limits::default()).is_err(),
            "U+{:04X} in a tag",
            c as u32
        );
    }
    // Universally agreed escapes stay allowed.
    assert!(
        id.sign_event(&tpl(1, "\t\n\r\u{08}\u{0c}"), &Limits::default())
            .is_ok()
    );

    // Opt-in: the id then equals what nostr-tools 2.26.1 computes (vector from interop run).
    let permissive = Limits {
        allow_ambiguous_control_chars: true,
        ..Limits::default()
    };
    let key = Identity::from_secret_str(
        "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
    )
    .unwrap();
    let ev = key
        .sign_event(&tpl(1, "control \u{01} x"), &permissive)
        .unwrap();
    assert_eq!(
        ev.id.to_hex(),
        "be7f06c616d7f9cac204405b4045c3c5731bc761e7ce99494224c20fddfc6bb1"
    );
}

#[test]
fn signature_is_bound_to_the_event_contents() {
    let id = Identity::generate();
    let ev = id
        .sign_event(&tpl(1, "original"), &Limits::default())
        .unwrap();
    ev.verify().unwrap();
    let mut json: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
    json["content"] = "tampered".into();
    let forged: nostr::event::Event = serde_json::from_value(json).unwrap();
    assert!(forged.verify().is_err());
}

#[test]
fn created_at_defaults_to_now() {
    let id = Identity::generate();
    let mut t = tpl(1, "now");
    t.created_at = None;
    let before = nostr::types::Timestamp::now().as_secs();
    let ev = id.sign_event(&t, &Limits::default()).unwrap();
    let after = nostr::types::Timestamp::now().as_secs();
    assert!((before..=after).contains(&ev.created_at.as_secs()));
}

#[test]
fn json_templates_are_parsed_strictly() {
    let limits = Limits::default();
    let ok = r#"{"kind":1,"content":"hi","tags":[["t","x"]],"created_at":1700000000}"#;
    assert!(EventTemplate::from_json(ok, &limits).is_ok());
    // Defaults for omitted fields.
    let minimal = EventTemplate::from_json(r#"{"kind":1}"#, &limits).unwrap();
    assert_eq!(
        (
            minimal.content.as_str(),
            minimal.tags.len(),
            minimal.created_at
        ),
        ("", 0, None)
    );

    let rejected = [
        (r#"{"content":"no kind"}"#, "missing kind"),
        (r#"{"kind":65536}"#, "kind out of range"),
        (r#"{"kind":-1}"#, "negative kind"),
        (r#"{"kind":"1"}"#, "kind as string"),
        (r#"{"kind":1,"sig":"00"}"#, "sig must not be accepted"),
        (r#"{"kind":1,"extra":true}"#, "unknown field"),
        (r#"{"kind":1,"tags":[[]]}"#, "empty tag"),
        (r#"{"kind":1,"tags":[["a",1]]}"#, "non-string tag element"),
        (r#"{"kind":1,"tags":[["a",null]]}"#, "null tag element"),
        (r#"{"kind":1,"content":null}"#, "null content"),
        (r#"{"kind":1,"pubkey":"nothex"}"#, "bad pubkey"),
        (r#"{"kind":1,"id":"abcd"}"#, "bad id"),
        (r#"{"kind":1,"created_at":-5}"#, "negative created_at"),
        (r#"{"kind":1} trailing"#, "trailing garbage"),
        ("", "empty"),
        ("[]", "array"),
        ("null", "null"),
    ];
    for (json, why) in rejected {
        assert!(
            EventTemplate::from_json(json, &limits).is_err(),
            "should reject: {why}"
        );
    }
}

#[test]
fn claimed_pubkey_and_id_are_verified_not_trusted() {
    let me = Identity::generate();
    let other = Identity::generate();
    let limits = Limits::default();

    // Wrong pubkey -> mismatch.
    let mut t = tpl(1, "x");
    t.pubkey = Some(other.pubkey_hex());
    assert!(matches!(
        me.sign_event(&t, &limits),
        Err(CryptoError::PubkeyMismatch)
    ));

    // Right pubkey (any hex case) -> ok.
    t.pubkey = Some(me.pubkey_hex().to_uppercase());
    assert!(me.sign_event(&t, &limits).is_ok());

    // Right id -> ok; wrong id -> refused.
    let good_id = nip01_id(&me.pubkey_hex(), 1_700_000_000, 1, &[], "x");
    let mut t = tpl(1, "x");
    t.id = Some(good_id);
    assert!(me.sign_event(&t, &limits).is_ok());
    t.id = Some("00".repeat(32));
    assert!(matches!(
        me.sign_event(&t, &limits),
        Err(CryptoError::InvalidEvent(_))
    ));
}

#[test]
fn limits_are_enforced() {
    let id = Identity::generate();
    let tight = Limits {
        max_content_bytes: 10,
        max_tags: 2,
        max_tag_items: 3,
        max_tag_item_bytes: 5,
        max_template_bytes: 200,
        ..Limits::default()
    };
    let mut t = tpl(1, "short");
    assert!(id.sign_event(&t, &tight).is_ok());

    t.content = "x".repeat(11);
    assert!(matches!(
        id.sign_event(&t, &tight),
        Err(CryptoError::LimitExceeded { .. })
    ));

    let mut t = tpl(1, "");
    t.tags = vec![vec!["a".into()]; 3];
    assert!(matches!(
        id.sign_event(&t, &tight),
        Err(CryptoError::LimitExceeded { .. })
    ));

    let mut t = tpl(1, "");
    t.tags = vec![vec!["a".into(); 4]];
    assert!(matches!(
        id.sign_event(&t, &tight),
        Err(CryptoError::LimitExceeded { .. })
    ));

    let mut t = tpl(1, "");
    t.tags = vec![vec!["abcdef".into()]];
    assert!(matches!(
        id.sign_event(&t, &tight),
        Err(CryptoError::LimitExceeded { .. })
    ));

    let huge = format!(r#"{{"kind":1,"content":"{}"}}"#, "y".repeat(300));
    assert!(matches!(
        EventTemplate::from_json(&huge, &tight),
        Err(CryptoError::LimitExceeded { .. })
    ));
}

#[test]
fn identities_are_isolated() {
    let a = Identity::generate();
    let b = Identity::generate();
    let ea = a.sign_event(&tpl(1, "same"), &Limits::default()).unwrap();
    let eb = b.sign_event(&tpl(1, "same"), &Limits::default()).unwrap();
    assert_ne!(ea.pubkey, eb.pubkey);
    assert_ne!(ea.id, eb.id);
    assert_ne!(ea.sig, eb.sig);
}

#[test]
fn debug_output_never_contains_secret() {
    let id = Identity::generate();
    let secret_hex = hex::encode(*id.secret_bytes());
    let dbg = format!("{id:?}");
    assert!(!dbg.contains(&secret_hex));
    assert!(dbg.contains(&id.pubkey_hex()));
}
