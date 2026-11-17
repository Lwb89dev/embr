//! Password key derivation (Argon2id) and the authenticated-encryption helpers.
//!
//! No primitives are implemented here: Argon2id comes from the RustCrypto `argon2` crate and
//! XChaCha20-Poly1305 from `chacha20poly1305`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::VaultError;

/// Minimum number of characters (after NFKC normalisation) of a vault password.
pub const MIN_PASSWORD_CHARS: usize = 10;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// Default for new vaults: 256 MiB, 3 passes, 4 lanes. Above the OWASP minimum
    /// (19 MiB, t=2) and the RFC 9106 memory-constrained recommendation (64 MiB, t=3, p=4). The
    /// lanes are evaluated sequentially (we do not enable argon2's `parallel` feature), so the
    /// cost is `m × t`; on the development machine that is ≈0.3 s per unlock (see
    /// `docs/BENCHMARKS.md`). That cost is the main defence against offline guessing of a stolen
    /// vault file; the memory is allocated only transiently, during unlock.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 262_144,
        t_cost: 3,
        p_cost: 4,
    };

    /// The weakest parameters accepted for a *new* vault (OWASP minimum configuration). Intended
    /// for tests and very constrained devices; not a recommendation.
    pub const MINIMUM: KdfParams = KdfParams {
        m_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    /// Largest accepted values. Applied to every file read, so a hostile vault file cannot make
    /// us allocate unbounded memory or burn unbounded CPU before authentication.
    const MAX_M_KIB: u32 = 1024 * 1024; // 1 GiB
    const MAX_T: u32 = 16;
    const MAX_P: u32 = 16;

    pub(crate) fn check_upper_bounds(&self) -> Result<(), VaultError> {
        if self.m_kib == 0
            || self.t_cost == 0
            || self.p_cost == 0
            || self.m_kib > Self::MAX_M_KIB
            || self.t_cost > Self::MAX_T
            || self.p_cost > Self::MAX_P
        {
            return Err(VaultError::KdfParams);
        }
        Ok(())
    }

    /// Validates parameters chosen for a new vault or a password change.
    pub fn validate_for_new(&self) -> Result<(), VaultError> {
        self.check_upper_bounds()?;
        if self.m_kib < Self::MINIMUM.m_kib
            || self.t_cost < Self::MINIMUM.t_cost
            || self.p_cost < Self::MINIMUM.p_cost
        {
            return Err(VaultError::KdfParams);
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// NFKC-normalises a password (consistent across platforms and input methods) and enforces the
/// minimum length. The result is zeroised on drop.
pub(crate) fn normalise_new_password(password: &str) -> Result<Zeroizing<String>, VaultError> {
    let p = normalise(password);
    if p.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::PasswordTooShort {
            min: MIN_PASSWORD_CHARS,
        });
    }
    Ok(p)
}

/// NFKC-normalises without enforcing length (for verifying an existing password).
pub(crate) fn normalise(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.nfkc().collect())
}

/// Argon2id(password, salt) → 32-byte key-encryption key.
pub(crate) fn derive_kek(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    params.check_upper_bounds()?;
    let p = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| VaultError::KdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| VaultError::KdfParams)?;
    Ok(out)
}

/// Fills a fresh array with OS randomness.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| VaultError::Rng)?;
    Ok(buf)
}

/// XChaCha20-Poly1305 seal. The nonce is 192-bit random, so collisions are not a concern.
pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Malformed("encryption failed"))
}

/// XChaCha20-Poly1305 open. The plaintext is returned in a zeroising buffer.
pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let nonce: &[u8; 24] = nonce
        .try_into()
        .map_err(|_| VaultError::Malformed("bad nonce length"))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)
}
