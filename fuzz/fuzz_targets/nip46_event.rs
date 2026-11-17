//! Arbitrary event JSON delivered by a hostile relay: the NIP-46 front door must never panic and
//! must never accept an event that is not addressed to us, correctly signed and decryptable.
#![no_main]
use embr_crypto::{Event, Identity, Limits};
use embr_nip46::protocol::{addressed_to, open_request, open_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(ev) = serde_json::from_slice::<Event>(data) else { return };
    let signer = Identity::from_secret_bytes(&[5u8; 32]).expect("fixed key is valid");
    let _ = addressed_to(&ev);
    // A random event cannot be a valid request for our key (it would need a valid signature, our
    // p-tag and a NIP-44 payload we can open).
    assert!(open_request(&signer, &ev, &Limits::default()).is_err());
    let _ = open_response(&signer, &ev, &Limits::default());
});
