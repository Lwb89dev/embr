//! Client authentication: proof of possession of the client key.
//!
//! After the server's hello (which carries a fresh nonce) the client sends a **signed Nostr event**
//! of kind [`AUTH_EVENT_KIND`] (ephemeral range, private to this protocol, never to be published)
//! with tags `["embr_nonce", <nonce>]` and `["embr_proto", "1"]` and empty content. Using an event
//! means every Nostr library can produce the proof without new cryptography.
//!
//! The server accepts the proof only if: the signature and id verify, the author equals the
//! claimed client key, the nonce is the one it just issued on *this* connection (so a recorded
//! hello cannot be replayed on another), and `created_at` is within [`MAX_PROOF_SKEW_SECS`] of its
//! clock.

use embr_core::Pubkey32;
use embr_crypto::{Event, EventTemplate, Identity, Limits};
use serde_json::Value;

/// Event kind of the authentication proof.
pub const AUTH_EVENT_KIND: u16 = 27183;
/// Maximum accepted difference between the proof's `created_at` and the server clock.
pub const MAX_PROOF_SKEW_SECS: u64 = 120;
const NONCE_TAG: &str = "embr_nonce";
const PROTO_TAG: &str = "embr_proto";

/// Authentication failures. Deliberately coarse: the peer learns *that* it failed, not why.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// The proof is missing, malformed, mis-signed, stale, or for another connection.
    #[error("invalid proof")]
    InvalidProof,
    /// The operating system's random number generator failed.
    #[error("random number generator failed")]
    Rng,
}

/// A fresh 256-bit nonce as 64 lowercase hex characters.
pub fn new_nonce() -> Result<String, AuthError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| AuthError::Rng)?;
    Ok(hex::encode(b))
}

/// Client side: builds the proof for `nonce` with the client key.
pub fn make_proof(identity: &Identity, nonce: &str, now: u64) -> Result<Value, AuthError> {
    let tpl = EventTemplate {
        kind: AUTH_EVENT_KIND,
        content: String::new(),
        tags: vec![
            vec![NONCE_TAG.to_owned(), nonce.to_owned()],
            vec![PROTO_TAG.to_owned(), crate::PROTOCOL_VERSION.to_string()],
        ],
        created_at: Some(now),
        pubkey: None,
        id: None,
    };
    let event = identity
        .sign_event(&tpl, &Limits::default())
        .map_err(|_| AuthError::InvalidProof)?;
    serde_json::to_value(event).map_err(|_| AuthError::InvalidProof)
}

/// Server side: verifies `proof` against the nonce issued on this connection and the key the
/// client claimed.
pub fn verify_proof(
    proof: &Value,
    nonce: &str,
    claimed: &Pubkey32,
    now: u64,
) -> Result<(), AuthError> {
    let event: Event =
        serde_json::from_value(proof.clone()).map_err(|_| AuthError::InvalidProof)?;
    if event.kind.as_u16() != AUTH_EVENT_KIND || !event.content.is_empty() {
        return Err(AuthError::InvalidProof);
    }
    if event.pubkey.to_hex() != claimed.to_string() {
        return Err(AuthError::InvalidProof);
    }
    if event.created_at.as_secs().abs_diff(now) > MAX_PROOF_SKEW_SECS {
        return Err(AuthError::InvalidProof);
    }
    let has = |name: &str, value: &str| {
        event
            .tags
            .iter()
            .any(|t| matches!(t.as_slice(), [k, v] if k == name && v == value))
    };
    if !has(NONCE_TAG, nonce) || !has(PROTO_TAG, &crate::PROTOCOL_VERSION.to_string()) {
        return Err(AuthError::InvalidProof);
    }
    event.verify().map_err(|_| AuthError::InvalidProof)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn pk(id: &Identity) -> Pubkey32 {
        id.pubkey_hex().parse().unwrap()
    }

    #[test]
    fn valid_proof_verifies() {
        let id = Identity::generate();
        let nonce = new_nonce().unwrap();
        assert_eq!(nonce.len(), 64);
        let proof = make_proof(&id, &nonce, NOW).unwrap();
        verify_proof(&proof, &nonce, &pk(&id), NOW).unwrap();
        verify_proof(&proof, &nonce, &pk(&id), NOW + MAX_PROOF_SKEW_SECS).unwrap();
    }

    #[test]
    fn nonces_are_unique() {
        assert_ne!(new_nonce().unwrap(), new_nonce().unwrap());
    }

    #[test]
    fn replay_on_another_connection_fails() {
        let id = Identity::generate();
        let proof = make_proof(&id, &new_nonce().unwrap(), NOW).unwrap();
        assert!(verify_proof(&proof, &new_nonce().unwrap(), &pk(&id), NOW).is_err());
    }

    #[test]
    fn wrong_claimed_key_fails() {
        let a = Identity::generate();
        let b = Identity::generate();
        let nonce = new_nonce().unwrap();
        let proof = make_proof(&a, &nonce, NOW).unwrap();
        assert!(
            verify_proof(&proof, &nonce, &pk(&b), NOW).is_err(),
            "claiming someone else's key"
        );
    }

    #[test]
    fn stale_or_future_proofs_fail() {
        let id = Identity::generate();
        let nonce = new_nonce().unwrap();
        let proof = make_proof(&id, &nonce, NOW).unwrap();
        assert!(verify_proof(&proof, &nonce, &pk(&id), NOW + MAX_PROOF_SKEW_SECS + 1).is_err());
        assert!(verify_proof(&proof, &nonce, &pk(&id), NOW - MAX_PROOF_SKEW_SECS - 1).is_err());
    }

    #[test]
    fn forged_or_malformed_proofs_fail() {
        let id = Identity::generate();
        let nonce = new_nonce().unwrap();
        let mut proof = make_proof(&id, &nonce, NOW).unwrap();
        // Tampered content invalidates the signature.
        proof["content"] = "x".into();
        assert!(verify_proof(&proof, &nonce, &pk(&id), NOW).is_err());
        for bad in [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!("sig"),
        ] {
            assert!(verify_proof(&bad, &nonce, &pk(&id), NOW).is_err());
        }
    }

    #[test]
    fn an_ordinary_nostr_event_is_not_a_proof() {
        let id = Identity::generate();
        let nonce = new_nonce().unwrap();
        // Right shape but wrong kind (e.g. a note the client signed elsewhere).
        let tpl = EventTemplate {
            kind: 1,
            content: String::new(),
            tags: vec![
                vec![NONCE_TAG.into(), nonce.clone()],
                vec![PROTO_TAG.into(), "1".into()],
            ],
            created_at: Some(NOW),
            pubkey: None,
            id: None,
        };
        let ev = id.sign_event(&tpl, &Limits::default()).unwrap();
        assert!(verify_proof(&serde_json::to_value(ev).unwrap(), &nonce, &pk(&id), NOW).is_err());
    }
}
