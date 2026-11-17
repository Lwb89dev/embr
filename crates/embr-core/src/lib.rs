//! Platform-independent shared types for the Embr Nostr signer.
//!
//! This crate deliberately has **no** cryptographic or I/O dependencies beyond the OS random
//! number generator. It defines the vocabulary shared by the vault, the policy engine, the IPC
//! layer and the NIP-46 transport:
//!
//! * [`AccountId`] – an opaque, random, local identifier of a vault account (never a key).
//! * [`Operation`] – the closed set of cryptographic operations the signer can perform.
//! * [`KeySecurity`] – the NIP-49 "key security byte" tracked per account.
//! * [`AccountMeta`] – public, non-secret account information that is safe to show in a UI.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors produced by this crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoreError {
    /// An [`AccountId`] was not 32 lowercase/uppercase hexadecimal characters.
    #[error("invalid account id: expected 32 hex characters")]
    InvalidAccountId,
    /// An [`Operation`] name was not recognised.
    #[error("unknown operation: {0:?}")]
    UnknownOperation(String),
    /// The operating system could not provide random bytes.
    #[error("operating system random number generator failed")]
    Rng,
}

/// Opaque identifier of an account inside a vault.
///
/// 128 random bits. It is **not** derived from the key material, so it reveals nothing about it,
/// and it stays stable when the account label changes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId([u8; 16]);

impl AccountId {
    /// Generates a fresh random identifier using the OS CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| CoreError::Rng)?;
        Ok(Self(bytes))
    }

    /// Builds an identifier from raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({self})")
    }
}

impl FromStr for AccountId {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 16];
        hex::decode_to_slice(s, &mut out).map_err(|_| CoreError::InvalidAccountId)?;
        Ok(Self(out))
    }
}

impl Serialize for AccountId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A cryptographic operation the signer can be asked to perform.
///
/// The set is closed on purpose: anything not listed here is *unsupported*, never "best effort".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Reveal the public key of an account (a login).
    GetPublicKey,
    /// Sign a Nostr event (NIP-01).
    SignEvent,
    /// NIP-44 encryption.
    Nip44Encrypt,
    /// NIP-44 decryption (returns plaintext to the caller).
    Nip44Decrypt,
    /// NIP-04 encryption (legacy).
    Nip04Encrypt,
    /// NIP-04 decryption (legacy, returns plaintext to the caller).
    Nip04Decrypt,
}

impl Operation {
    /// Every operation, in a stable order.
    pub const ALL: [Operation; 6] = [
        Operation::GetPublicKey,
        Operation::SignEvent,
        Operation::Nip44Encrypt,
        Operation::Nip44Decrypt,
        Operation::Nip04Encrypt,
        Operation::Nip04Decrypt,
    ];

    /// Wire name, identical to the NIP-46 method name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Operation::GetPublicKey => "get_public_key",
            Operation::SignEvent => "sign_event",
            Operation::Nip44Encrypt => "nip44_encrypt",
            Operation::Nip44Decrypt => "nip44_decrypt",
            Operation::Nip04Encrypt => "nip04_encrypt",
            Operation::Nip04Decrypt => "nip04_decrypt",
        }
    }

    /// `true` for NIP-04, which is kept only for backward compatibility and must be shown as
    /// legacy in every user interface.
    pub const fn is_legacy(self) -> bool {
        matches!(self, Operation::Nip04Encrypt | Operation::Nip04Decrypt)
    }

    /// `true` when the operation returns *plaintext of someone's private message* to the caller.
    ///
    /// Such operations must never be implicitly covered by a signing permission.
    pub const fn reveals_plaintext(self) -> bool {
        matches!(self, Operation::Nip44Decrypt | Operation::Nip04Decrypt)
    }

    /// `true` when the operation produces a signature that third parties will attribute to the
    /// user.
    pub const fn produces_signature(self) -> bool {
        matches!(self, Operation::SignEvent)
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Operation {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Operation::ALL
            .into_iter()
            .find(|op| op.as_str() == s)
            .ok_or_else(|| CoreError::UnknownOperation(s.to_owned()))
    }
}

/// NIP-49 "key security byte": what is known about how the key has been handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySecurity {
    /// The key has been handled insecurely at some point (pasted, stored unencrypted, ...).
    Weak,
    /// The key has never been handled insecurely, as far as Embr knows (generated inside Embr).
    Medium,
    /// Nothing is known about the key's history.
    Unknown,
}

/// Public, non-secret information about an account. Safe to send to a UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountMeta {
    /// Local identifier.
    pub id: AccountId,
    /// Human-readable label chosen by the user.
    pub label: String,
    /// Public key, lowercase hex (x-only, 32 bytes).
    pub pubkey_hex: String,
    /// Public key as `npub1…`.
    pub npub: String,
    /// Creation (or import) time, Unix seconds.
    pub created_at: u64,
    /// What is known about how the key was handled.
    pub key_security: KeySecurity,
    /// Whether the account has an avatar image.
    pub has_avatar: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn account_id_roundtrip() {
        let id = AccountId::generate().unwrap();
        let s = id.to_string();
        assert_eq!(s.len(), 32);
        assert_eq!(s.parse::<AccountId>().unwrap(), id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{s}\""));
        assert_eq!(serde_json::from_str::<AccountId>(&json).unwrap(), id);
    }

    #[test]
    fn account_ids_are_unique() {
        let a = AccountId::generate().unwrap();
        let b = AccountId::generate().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn account_id_rejects_garbage() {
        assert_eq!("".parse::<AccountId>(), Err(CoreError::InvalidAccountId));
        assert_eq!(
            "zz".repeat(16).parse::<AccountId>(),
            Err(CoreError::InvalidAccountId)
        );
        assert_eq!(
            "ab".repeat(15).parse::<AccountId>(),
            Err(CoreError::InvalidAccountId)
        );
        assert_eq!(
            "ab".repeat(17).parse::<AccountId>(),
            Err(CoreError::InvalidAccountId)
        );
    }

    #[test]
    fn operation_names_match_nip46_and_roundtrip() {
        for op in Operation::ALL {
            assert_eq!(op.as_str().parse::<Operation>().unwrap(), op);
            let json = serde_json::to_string(&op).unwrap();
            assert_eq!(json, format!("\"{}\"", op.as_str()));
        }
        assert!("sign_psbt".parse::<Operation>().is_err());
    }

    #[test]
    fn decrypt_is_not_signing() {
        for op in Operation::ALL {
            assert!(!(op.reveals_plaintext() && op.produces_signature()));
        }
        assert!(Operation::Nip44Decrypt.reveals_plaintext());
        assert!(Operation::Nip04Decrypt.reveals_plaintext());
        assert!(!Operation::Nip44Encrypt.reveals_plaintext());
        assert!(Operation::Nip04Encrypt.is_legacy());
        assert!(!Operation::Nip44Encrypt.is_legacy());
    }
}
