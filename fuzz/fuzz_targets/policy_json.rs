//! Stored policy data (hostile if the vault were ever tampered with and re-keyed): loading must
//! never panic, and whatever loads must still be default-deny and respect the sensitive-kind rule.
#![no_main]
use embr_core::{AccountId, Operation, Pubkey32};
use embr_policy::{Engine, Request, SENSITIVE_KINDS, SessionId, Verdict};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut e) = Engine::from_json(data, 1_700_000_000) {
        let _ = e.to_json();
        let stranger = Request {
            client: Pubkey32::from_bytes([0xEE; 32]),
            account: AccountId::from_bytes([0xEE; 16]),
            op: Operation::SignEvent,
            kind: Some(1),
            peer: None,
        };
        assert!(!matches!(e.evaluate(&stranger, SessionId(1), 1_700_000_000), Verdict::Allow { .. }));
        // An any-kind allow never covers DM kinds, whatever was stored.
        for client in e.clients().to_vec() {
            for account in client.accounts.clone() {
                for kind in SENSITIVE_KINDS {
                    let req = Request { client: client.key, account, op: Operation::SignEvent, kind: Some(kind), peer: None };
                    if let Verdict::Allow { grant: Some(g) } = e.evaluate(&req, SessionId(2), 1_700_000_000) {
                        let ok = e.grants().iter().any(|x| x.id == g && matches!(x.kind, embr_policy::KindScope::Exact(k) if k == kind));
                        assert!(ok || e.grants().iter().all(|x| x.id != g), "DM kind {kind} allowed by a non-exact grant");
                    }
                }
            }
        }
    }
});
