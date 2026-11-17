//! [`Identity`]: the only type in the workspace that owns secret key material.

use std::fmt;

use embr_core::KeySecurity;
use nostr::event::{Event, Kind, SignEvent, Tag, UnsignedEvent};
use nostr::key::{Keys, PublicKey, SecretKey};
use nostr::nips::nip04;
use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::nips::nip44;
use nostr::nips::nip49::{self, EncryptedSecretKey};
use nostr::types::Timestamp;
use zeroize::Zeroizing;

use crate::template::{EventTemplate, Limits};
use crate::{CryptoError, encode_npub};

/// Lowest scrypt `log_n` accepted for NIP-49 *export* (64 MiB, the NIP-49 table's lower bound).
pub const MIN_EXPORT_LOG_N: u8 = 16;
/// Highest scrypt `log_n` accepted for NIP-49 *export* (1 GiB).
pub const MAX_EXPORT_LOG_N: u8 = 20;

/// A Nostr identity: a secp256k1 key pair whose secret half never leaves this type unless the
/// caller asks for it explicitly with [`Identity::secret_bytes`] / [`Identity::reveal_nsec`] /
/// [`Identity::export_ncryptsec`].
///
/// * Not `Clone`, not `Display`; `Debug` shows only the public key.
/// * The secret key is erased on drop by `nostr::SecretKey` (best effort: see
///   `docs/THREAT_MODEL.md` for the limits of memory scrubbing).
pub struct Identity {
    keys: Keys,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("pubkey", &self.keys.public_key().to_hex())
            .finish()
    }
}

impl Identity {
    // ----- construction ------------------------------------------------------------------

    /// Generates a new identity using the operating system's CSPRNG.
    pub fn generate() -> Self {
        Self {
            keys: Keys::generate(),
        }
    }

    /// Builds an identity from a secret key given as `nsec1…` or 64 hexadecimal characters.
    ///
    /// Nothing else is accepted (not `ncryptsec`, not `npub`, not a mnemonic): callers must
    /// decide explicitly what they are importing.
    pub fn from_secret_str(s: &str) -> Result<Self, CryptoError> {
        let s = s.trim();
        let sk = if s.starts_with("nsec1") {
            SecretKey::from_bech32(s).map_err(|_| CryptoError::InvalidSecretKey)?
        } else if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            SecretKey::from_hex(s).map_err(|_| CryptoError::InvalidSecretKey)?
        } else {
            return Err(CryptoError::InvalidSecretKey);
        };
        Ok(Self {
            keys: Keys::new(sk),
        })
    }

    /// Builds an identity from 32 raw secret-key bytes. Fails for zero or out-of-range scalars.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let sk = SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidSecretKey)?;
        Ok(Self {
            keys: Keys::new(sk),
        })
    }

    /// Decrypts a NIP-49 `ncryptsec1…` string.
    ///
    /// Returns the identity together with the key-security byte stored in the backup.
    /// The scrypt cost declared in the (untrusted) payload is bounded by
    /// [`Limits::max_ncryptsec_log_n`] to prevent memory-exhaustion attacks.
    pub fn from_ncryptsec(
        ncryptsec: &str,
        password: &str,
        limits: &Limits,
    ) -> Result<(Self, KeySecurity), CryptoError> {
        let enc = EncryptedSecretKey::from_bech32(ncryptsec.trim())
            .map_err(|_| CryptoError::InvalidNcryptsec)?;
        if enc.log_n() > limits.max_ncryptsec_log_n {
            return Err(CryptoError::InvalidNcryptsec);
        }
        let security = from_nip49_security(enc.key_security());
        let sk = enc
            .decrypt_with_max_log_n(password, limits.max_ncryptsec_log_n)
            .map_err(|_| CryptoError::WrongPasswordOrCorrupt)?;
        Ok((
            Self {
                keys: Keys::new(sk),
            },
            security,
        ))
    }

    // ----- public information ------------------------------------------------------------

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// The public key as lowercase hex.
    pub fn pubkey_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }

    /// The public key as `npub1…`.
    pub fn npub(&self) -> String {
        encode_npub(&self.keys.public_key())
    }

    // ----- secret export (explicit, named, zeroising) ------------------------------------

    /// The 32 raw secret bytes, in a buffer that is zeroised on drop.
    ///
    /// Intended for the vault's serialisation only.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.keys.secret_key().to_secret_bytes())
    }

    /// The secret key as `nsec1…`. **Reveals the private key.** The caller must have obtained
    /// explicit user consent (and should require password re-entry) before calling this.
    pub fn reveal_nsec(&self) -> Result<Zeroizing<String>, CryptoError> {
        self.keys
            .secret_key()
            .to_bech32()
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Exports the secret key as a NIP-49 `ncryptsec1…` string protected by `password`.
    ///
    /// `log_n` must be within [`MIN_EXPORT_LOG_N`]..=[`MAX_EXPORT_LOG_N`].
    pub fn export_ncryptsec(
        &self,
        password: &str,
        log_n: u8,
        security: KeySecurity,
    ) -> Result<String, CryptoError> {
        if !(MIN_EXPORT_LOG_N..=MAX_EXPORT_LOG_N).contains(&log_n) {
            return Err(CryptoError::InvalidScryptCost {
                min: MIN_EXPORT_LOG_N,
                max: MAX_EXPORT_LOG_N,
            });
        }
        let enc = EncryptedSecretKey::new(
            self.keys.secret_key(),
            password,
            log_n,
            to_nip49_security(security),
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
        enc.to_bech32().map_err(|_| CryptoError::EncryptionFailed)
    }

    // ----- NIP-01 signing ----------------------------------------------------------------

    /// Validates `template` and signs it with this identity (NIP-01, BIP-340 Schnorr).
    ///
    /// Guarantees:
    /// * the event's `pubkey` is always this identity's key; a template naming another key is
    ///   rejected with [`CryptoError::PubkeyMismatch`];
    /// * a client-supplied `id` is verified against the computed one, never trusted;
    /// * the returned event has been verified (id and signature) before it is handed out.
    pub fn sign_event(
        &self,
        template: &EventTemplate,
        limits: &Limits,
    ) -> Result<Event, CryptoError> {
        template.validate(limits)?;
        let pk = self.keys.public_key();

        if let Some(claimed) = &template.pubkey {
            let claimed = PublicKey::from_hex(claimed)
                .map_err(|_| CryptoError::InvalidEvent("bad pubkey".into()))?;
            if claimed != pk {
                return Err(CryptoError::PubkeyMismatch);
            }
        }

        let tags = template
            .tags
            .iter()
            .map(|t| Tag::parse(t.iter().cloned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CryptoError::InvalidEvent("invalid tag".into()))?;
        let created_at = template
            .created_at
            .map(Timestamp::from_secs)
            .unwrap_or_else(Timestamp::now);
        let unsigned = UnsignedEvent::new(
            pk,
            created_at,
            Kind::from(template.kind),
            tags,
            template.content.clone(),
        );

        if let Some(claimed_id) = &template.id {
            if !claimed_id.eq_ignore_ascii_case(&unsigned.compute_id().to_hex()) {
                return Err(CryptoError::InvalidEvent(
                    "id does not match event contents".into(),
                ));
            }
        }

        let event = self
            .keys
            .sign_event(unsigned)
            .map_err(|_| CryptoError::SigningFailed)?;
        // Belt and braces: never hand out an event that does not verify.
        event.verify().map_err(|_| CryptoError::SigningFailed)?;
        Ok(event)
    }

    // ----- NIP-44 (preferred) ------------------------------------------------------------

    /// NIP-44 v2 encryption of `plaintext` for `peer`.
    pub fn nip44_encrypt(
        &self,
        peer: &PublicKey,
        plaintext: &str,
        limits: &Limits,
    ) -> Result<String, CryptoError> {
        if plaintext.len() > limits.max_plaintext_bytes {
            return Err(CryptoError::LimitExceeded {
                what: "plaintext size",
                limit: limits.max_plaintext_bytes,
            });
        }
        nip44::encrypt(self.keys.secret_key(), peer, plaintext, nip44::Version::V2)
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    /// NIP-44 decryption of a payload from `peer`. The plaintext is returned in a zeroising
    /// buffer.
    pub fn nip44_decrypt(
        &self,
        peer: &PublicKey,
        payload: &str,
        limits: &Limits,
    ) -> Result<Zeroizing<String>, CryptoError> {
        if payload.len() > limits.max_ciphertext_bytes {
            return Err(CryptoError::LimitExceeded {
                what: "ciphertext size",
                limit: limits.max_ciphertext_bytes,
            });
        }
        nip44::decrypt(self.keys.secret_key(), peer, payload)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    // ----- NIP-04 (LEGACY) ---------------------------------------------------------------

    /// **Legacy.** NIP-04 encryption. Unauthenticated AES-CBC, leaks metadata, and deprecated
    /// by the Nostr specification; kept only for backward compatibility. Prefer
    /// [`Identity::nip44_encrypt`].
    pub fn nip04_encrypt(
        &self,
        peer: &PublicKey,
        plaintext: &str,
        limits: &Limits,
    ) -> Result<String, CryptoError> {
        if plaintext.len() > limits.max_plaintext_bytes {
            return Err(CryptoError::LimitExceeded {
                what: "plaintext size",
                limit: limits.max_plaintext_bytes,
            });
        }
        nip04::encrypt(self.keys.secret_key(), peer, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    /// **Legacy.** NIP-04 decryption. See [`Identity::nip04_encrypt`].
    pub fn nip04_decrypt(
        &self,
        peer: &PublicKey,
        payload: &str,
        limits: &Limits,
    ) -> Result<Zeroizing<String>, CryptoError> {
        if payload.len() > limits.max_ciphertext_bytes {
            return Err(CryptoError::LimitExceeded {
                what: "ciphertext size",
                limit: limits.max_ciphertext_bytes,
            });
        }
        nip04::decrypt(self.keys.secret_key(), peer, payload)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

fn to_nip49_security(s: KeySecurity) -> nip49::KeySecurity {
    match s {
        KeySecurity::Weak => nip49::KeySecurity::Weak,
        KeySecurity::Medium => nip49::KeySecurity::Medium,
        KeySecurity::Unknown => nip49::KeySecurity::Unknown,
    }
}

fn from_nip49_security(s: nip49::KeySecurity) -> KeySecurity {
    match s {
        nip49::KeySecurity::Weak => KeySecurity::Weak,
        nip49::KeySecurity::Medium => KeySecurity::Medium,
        nip49::KeySecurity::Unknown => KeySecurity::Unknown,
    }
}
