//! Strict parsing and encoding of public keys.

use nostr::key::PublicKey;
use nostr::nips::nip19::{FromBech32, ToBech32};

use crate::CryptoError;

/// Parses a peer public key given as `npub1…` or as 64 hexadecimal characters.
///
/// This is intentionally stricter than `nostr::PublicKey::parse`, which also accepts `nprofile`
/// and `nostr:` URIs. NIP-46/NIP-55 style APIs carry plain keys; anything else is rejected so
/// that "what the user approved" and "what the signer used" cannot diverge.
pub fn parse_public_key(s: &str) -> Result<PublicKey, CryptoError> {
    if s.starts_with("npub1") {
        return PublicKey::from_bech32(s).map_err(|_| CryptoError::InvalidPublicKey);
    }
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return PublicKey::from_hex(s).map_err(|_| CryptoError::InvalidPublicKey);
    }
    Err(CryptoError::InvalidPublicKey)
}

/// Encodes a public key as `npub1…` (NIP-19).
pub fn encode_npub(pk: &PublicKey) -> String {
    // Encoding a 32-byte key cannot fail; fall back to hex rather than panic.
    pk.to_bech32().unwrap_or_else(|_| pk.to_hex())
}
