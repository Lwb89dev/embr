//! Attacker-controlled `bunker://` / `nostrconnect://` URIs and relay URLs: parse must never panic,
//! and whatever is accepted must satisfy the documented limits and re-parse after rendering.
#![no_main]
use embr_nip46::uri::{BunkerUri, MAX_PERMS, MAX_RELAYS, NostrConnectUri, validate_relay};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(r) = validate_relay(text) {
        assert!(r.starts_with("wss://") || r.starts_with("ws://"));
        assert!(validate_relay(&r).is_ok(), "normalised relay must stay valid");
    }
    if let Ok(b) = BunkerUri::parse(text) {
        assert!(b.relays.len() <= MAX_RELAYS);
        let again = BunkerUri::parse(&b.render()).expect("rendered URI must parse");
        assert_eq!(again, b);
    }
    if let Ok(n) = NostrConnectUri::parse(text) {
        assert!(!n.relays.is_empty() && n.relays.len() <= MAX_RELAYS && n.perms.len() <= MAX_PERMS);
    }
});
