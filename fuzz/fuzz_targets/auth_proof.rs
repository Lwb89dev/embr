//! The handshake proof is attacker-controlled JSON: verification must never panic and must only
//! ever accept a proof that really binds the nonce and the claimed key.
#![no_main]
use embr_core::Pubkey32;
use embr_ipc::auth::verify_proof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else { return };
    let nonce = "00".repeat(32);
    let claimed = Pubkey32::from_bytes([1u8; 32]);
    // A random JSON document essentially never carries a valid BIP-340 signature by this key.
    assert!(verify_proof(&v, &nonce, &claimed, 1_700_000_000).is_err());
});
