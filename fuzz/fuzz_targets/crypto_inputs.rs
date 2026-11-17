//! Untrusted keys and ciphertexts: parsing/decryption must fail cleanly, never panic.
#![no_main]
use embr_crypto::{Identity, Limits, parse_public_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let limits = Limits { max_ncryptsec_log_n: 12, ..Limits::default() }; // keep scrypt cheap while fuzzing
    let _ = Identity::from_secret_str(text);
    let _ = Identity::from_ncryptsec(text, "pw", &limits);
    let me = Identity::from_secret_bytes(&[9u8; 32]).expect("fixed key is valid");
    let peer = Identity::from_secret_bytes(&[3u8; 32]).expect("fixed key is valid").public_key();
    let _ = me.nip44_decrypt(&peer, text, &limits);
    let _ = me.nip04_decrypt(&peer, text, &limits);
    if let Ok(pk) = parse_public_key(text) {
        let _ = me.nip44_encrypt(&pk, "x", &limits);
    }
});
