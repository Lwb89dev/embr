//! Vault error type.
//!
//! Messages never contain secrets. A failed unlock deliberately does not distinguish "wrong
//! password" from "file was tampered with": with authenticated encryption they are the same
//! observable event.

use embr_crypto::CryptoError;

/// Errors produced by the vault.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The operation needs an unlocked vault.
    #[error("vault is locked")]
    Locked,
    /// `unlock` was called on an unlocked vault.
    #[error("vault is already unlocked")]
    AlreadyUnlocked,
    /// Wrong password, or the vault file was modified/corrupted.
    #[error("wrong password or corrupted vault")]
    WrongPasswordOrCorrupt,
    /// The vault file is structurally invalid.
    #[error("vault file is malformed: {0}")]
    Malformed(&'static str),
    /// The vault was written by a newer, incompatible version.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),
    /// A vault already exists at the destination.
    #[error("a vault already exists at this location")]
    AlreadyExists,
    /// No vault at this location.
    #[error("no vault found at this location")]
    NotFound,
    /// The password does not meet the minimum length.
    #[error("password too short (minimum {min} characters)")]
    PasswordTooShort {
        /// Minimum number of characters.
        min: usize,
    },
    /// No such account.
    #[error("account not found")]
    AccountNotFound,
    /// An account with the same public key is already in the vault.
    #[error("an account with this public key already exists")]
    DuplicateAccount,
    /// The label is not acceptable.
    #[error("invalid label: {0}")]
    InvalidLabel(&'static str),
    /// The avatar is not acceptable.
    #[error("invalid avatar: {0}")]
    InvalidAvatar(&'static str),
    /// An application blob was refused.
    #[error("invalid blob: {0}")]
    InvalidBlob(&'static str),
    /// The vault holds the maximum number of accounts.
    #[error("too many accounts (maximum {0})")]
    TooManyAccounts(usize),
    /// Argon2id parameters are outside the accepted range.
    #[error("key-derivation parameters are outside the accepted range")]
    KdfParams,
    /// The operating system's random number generator failed.
    #[error("operating system random number generator failed")]
    Rng,
    /// A cryptographic operation on a key failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// File-system error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
