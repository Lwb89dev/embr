//! Untrusted event templates: parse, validate, and (if accepted) sign without panicking; the
//! signed event must always verify and carry the signer's pubkey.
#![no_main]
use embr_crypto::{EventTemplate, Identity, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let limits = Limits { allow_ambiguous_control_chars: data.first().is_some_and(|b| b & 1 == 1), ..Limits::default() };
    if let Ok(tpl) = EventTemplate::from_json(text, &limits) {
        let id = Identity::from_secret_bytes(&[7u8; 32]).expect("fixed key is valid");
        if let Ok(ev) = id.sign_event(&tpl, &limits) {
            assert!(ev.verify().is_ok());
            assert_eq!(ev.pubkey, id.public_key());
        }
    }
});
