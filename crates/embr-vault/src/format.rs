//! On-disk format (version 1).
//!
//! ```text
//! {
//!   "magic": "embr-vault",
//!   "version": 1,
//!   "slots": [ { "type": "password",
//!                "kdf": { "alg": "argon2id", "v": 19, "m_kib": …, "t": …, "p": …, "salt": b64(16) },
//!                "nonce": b64(24), "wrapped_key": b64(48) } ],
//!   "body": { "nonce": b64(24), "ciphertext": b64(…) }
//! }
//! ```
//!
//! * `vault_key` (32 random bytes) encrypts the body with XChaCha20-Poly1305.
//! * Each *slot* wraps the vault key under a key-encryption key (KEK). Today there is a single
//!   `password` slot (KEK = Argon2id(NFKC(password), salt)). The array exists so that further
//!   slots (e.g. a key held by the OS keyring, an opt-in convenience) can be added without a
//!   format migration.
//! * AAD binds the wrapped key to its KDF parameters and the body to *all* slots, so mixing and
//!   matching parts of different files, or silently editing KDF parameters, fails authentication.
//!
//! Decrypted body layout: `[format: u8 = 1][meta_len: u32 LE][meta JSON][secret_0: 32 B]…`.
//! Secret keys are deliberately kept **out of the JSON** so that they never pass through a
//! general-purpose parser or allocator path that cannot be zeroised.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use embr_core::{AccountId, KeySecurity};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{KdfParams, VaultError};

pub(crate) const MAGIC: &str = "embr-vault";
pub(crate) const KDF_ALG: &str = "argon2id";
pub(crate) const VERSION: u32 = 1;
pub(crate) const BODY_FORMAT: u8 = 1;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;
/// Refuse to read vault files larger than this (accounts × avatars stay far below).
pub(crate) const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// Base64 (standard, padded) serde adapter for byte vectors.
mod b64 {
    use super::*;

    pub(super) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    pub(crate) magic: String,
    pub(crate) version: u32,
    pub(crate) slots: Vec<Slot>,
    pub(crate) body: Body,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Slot {
    Password(PasswordSlot),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordSlot {
    pub(crate) kdf: KdfDesc,
    #[serde(with = "b64")]
    pub(crate) nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub(crate) wrapped_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct KdfDesc {
    pub(crate) alg: String,
    pub(crate) v: u32,
    pub(crate) m_kib: u32,
    pub(crate) t: u32,
    pub(crate) p: u32,
    #[serde(with = "b64")]
    pub(crate) salt: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Body {
    #[serde(with = "b64")]
    pub(crate) nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub(crate) ciphertext: Vec<u8>,
}

impl Envelope {
    /// Parses and structurally validates an envelope (no cryptography, no heavy work).
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        let env: Envelope = serde_json::from_slice(bytes)
            .map_err(|_| VaultError::Malformed("not a valid vault file"))?;
        if env.magic != MAGIC {
            return Err(VaultError::Malformed("bad magic"));
        }
        if env.version != VERSION {
            return Err(VaultError::UnsupportedVersion(env.version));
        }
        if env.slots.len() != 1 {
            return Err(VaultError::Malformed("unexpected number of key slots"));
        }
        for slot in &env.slots {
            let Slot::Password(p) = slot;
            if p.kdf.alg != KDF_ALG || p.kdf.v != 0x13 {
                return Err(VaultError::Malformed("unsupported key-derivation function"));
            }
            if p.kdf.salt.len() != SALT_LEN
                || p.nonce.len() != NONCE_LEN
                || p.wrapped_key.len() != WRAPPED_KEY_LEN
            {
                return Err(VaultError::Malformed("bad slot field length"));
            }
            // Upper bounds only: a hostile file must not make us allocate gigabytes. Lower bounds
            // are enforced when *creating* parameters, not when reading old files.
            KdfParams {
                m_kib: p.kdf.m_kib,
                t_cost: p.kdf.t,
                p_cost: p.kdf.p,
            }
            .check_upper_bounds()?;
        }
        if env.body.nonce.len() != NONCE_LEN || env.body.ciphertext.len() < TAG_LEN {
            return Err(VaultError::Malformed("bad body field length"));
        }
        Ok(env)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let mut out = serde_json::to_vec_pretty(self)
            .map_err(|_| VaultError::Malformed("cannot serialise vault"))?;
        out.push(b'\n');
        Ok(out)
    }

    pub(crate) fn password_slot(&self) -> Result<&PasswordSlot, VaultError> {
        match self.slots.first() {
            Some(Slot::Password(p)) => Ok(p),
            None => Err(VaultError::Malformed("no password slot")),
        }
    }
}

impl PasswordSlot {
    pub(crate) fn kdf_params(&self) -> KdfParams {
        KdfParams {
            m_kib: self.kdf.m_kib,
            t_cost: self.kdf.t,
            p_cost: self.kdf.p,
        }
    }

    /// AAD that authenticates the wrapped key together with its KDF description.
    ///
    /// Defence in depth: the salt and cost parameters already determine the KEK, so changing any
    /// of them makes authentication fail regardless. Binding them here additionally covers
    /// future slot types that might not derive the KEK from these fields.
    pub(crate) fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(b"embr-vault/v1/slot/password\0");
        aad.extend_from_slice(&self.kdf.m_kib.to_le_bytes());
        aad.extend_from_slice(&self.kdf.t.to_le_bytes());
        aad.extend_from_slice(&self.kdf.p.to_le_bytes());
        aad.extend_from_slice(&self.kdf.salt);
        aad
    }
}

/// AAD that binds the body to every slot (including each slot's nonce and wrapped key).
pub(crate) fn body_aad(slots: &[Slot]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(256);
    aad.extend_from_slice(b"embr-vault/v1/body\0");
    aad.extend_from_slice(&(slots.len() as u32).to_le_bytes());
    for slot in slots {
        let Slot::Password(p) = slot;
        aad.extend_from_slice(&p.aad());
        aad.extend_from_slice(&p.nonce);
        aad.extend_from_slice(&p.wrapped_key);
    }
    aad
}

// ---- decrypted body --------------------------------------------------------------------

/// Non-secret per-account data stored (encrypted) in the body's JSON part.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredAccount {
    pub(crate) id: AccountId,
    pub(crate) label: String,
    pub(crate) pubkey_hex: String,
    pub(crate) created_at: u64,
    pub(crate) key_security: KeySecurity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) avatar: Option<StoredAvatar>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredAvatar {
    pub(crate) mime: String,
    #[serde(with = "b64")]
    pub(crate) data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyMeta {
    pub(crate) revision: u64,
    pub(crate) active: Option<AccountId>,
    pub(crate) accounts: Vec<StoredAccount>,
}
