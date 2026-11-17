//! Error type for the crypto crate.
//!
//! Messages are deliberately generic where the cause could leak information (e.g. a failed
//! decryption never says *which* check failed) and never contain key material or plaintext.

/// Errors produced by cryptographic operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// The string is not a valid secret key (`nsec1…` or 64 hexadecimal characters).
    #[error("invalid secret key (expected nsec1… or 64 hex characters)")]
    InvalidSecretKey,
    /// The string is not a valid public key (`npub1…` or 64 hexadecimal characters).
    #[error("invalid public key (expected npub1… or 64 hex characters)")]
    InvalidPublicKey,
    /// The event template is malformed or inconsistent.
    #[error("invalid event: {0}")]
    InvalidEvent(String),
    /// The template names a different public key than the signing identity.
    #[error("event pubkey does not match the signing identity")]
    PubkeyMismatch,
    /// An input exceeds a configured [`crate::Limits`] value.
    #[error("{what} exceeds the limit of {limit}")]
    LimitExceeded {
        /// Name of the limited quantity.
        what: &'static str,
        /// The configured limit.
        limit: usize,
    },
    /// Encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,
    /// Decryption failed (wrong key, corrupted or malformed payload, or invalid UTF-8).
    #[error("decryption failed")]
    DecryptionFailed,
    /// The `ncryptsec` string is malformed or uses unsupported parameters.
    #[error("invalid ncryptsec")]
    InvalidNcryptsec,
    /// Wrong password for an `ncryptsec` (or the payload was tampered with).
    #[error("wrong password or corrupted ncryptsec")]
    WrongPasswordOrCorrupt,
    /// The requested scrypt cost parameter is outside the accepted range.
    #[error("scrypt log_n must be between {min} and {max}")]
    InvalidScryptCost {
        /// Lowest accepted value.
        min: u8,
        /// Highest accepted value.
        max: u8,
    },
    /// Signing failed.
    #[error("signing failed")]
    SigningFailed,
    /// The operating system's random number generator failed.
    #[error("operating system random number generator failed")]
    Rng,
}
