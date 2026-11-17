//! Encrypted multi-account key vault for the Embr signer.
//!
//! The vault is the **only** place where private keys are persisted, and it persists them only
//! encrypted. Design (see `docs/ARCHITECTURE.md` and `docs/SECURITY.md`):
//!
//! * `password → Argon2id → KEK`; the KEK wraps a random 256-bit *vault key*; the vault key
//!   encrypts the account data with XChaCha20-Poly1305 ([`format`] documents the file layout).
//!   Changing the password re-wraps (and rotates) the vault key without touching accounts.
//! * Writes are atomic and crash-safe; files are created `0600` inside a `0700` directory.
//! * While the vault is **locked** no key material is in memory and every operation except
//!   [`Vault::unlock`] fails with [`VaultError::Locked`].
//! * Key material never leaves through a getter: callers get a closure-scoped `&Identity`
//!   ([`Vault::with_identity`]) or an explicit, password-re-authenticated export
//!   ([`Vault::export_ncryptsec`], [`Vault::reveal_nsec`]).
//! * Exports (NIP-49 `ncryptsec`) follow the NIP exactly (scrypt + XChaCha20-Poly1305, via
//!   `embr-crypto`); the *internal* format uses Argon2id.
//!
//! The type is not synchronised; the daemon owns it behind a mutex.

mod error;
mod format;
mod fsutil;
mod kdf;
mod validate;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use embr_core::{AccountId, AccountMeta, KeySecurity};
use embr_crypto::{Identity, Limits};
use zeroize::Zeroizing;

use crate::format::{
    BODY_FORMAT, Body, BodyMeta, Envelope, KDF_ALG, KEY_LEN, MAGIC, NONCE_LEN, PasswordSlot,
    SALT_LEN, Slot, StoredAccount, StoredAvatar, StoredBlob, VERSION, body_aad,
};

pub use error::VaultError;
pub use kdf::{KdfParams, MIN_PASSWORD_CHARS};
pub use validate::{MAX_AVATAR_BYTES, MAX_LABEL_CHARS};

/// Maximum number of accounts in one vault.
pub const MAX_ACCOUNTS: usize = 256;
/// Maximum number of application blobs.
pub const MAX_BLOBS: usize = 16;
/// Maximum size of one application blob.
pub const MAX_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// A decrypted avatar image (untrusted bytes; validated only by size and magic number).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avatar {
    /// `image/png`, `image/jpeg` or `image/webp`.
    pub mime: String,
    /// Image bytes.
    pub data: Vec<u8>,
}

struct Entry {
    stored: StoredAccount,
    identity: Identity,
}

struct Unlocked {
    vault_key: Zeroizing<[u8; KEY_LEN]>,
    entries: Vec<Entry>,
    active: Option<AccountId>,
    revision: u64,
    blobs: BTreeMap<String, StoredBlob>,
}

/// An encrypted vault file and, while unlocked, its decrypted accounts.
pub struct Vault {
    path: PathBuf,
    /// The envelope exactly as last written to (or read from) disk.
    envelope: Envelope,
    unlocked: Option<Unlocked>,
    /// Cost parameters used when the password is changed.
    kdf_for_new: KdfParams,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("unlocked", &self.unlocked.is_some())
            .finish()
    }
}

impl Vault {
    // ===== lifecycle ==================================================================

    /// Creates a new, empty vault protected by `password` with [`KdfParams::DEFAULT`].
    /// The returned vault is unlocked. Fails if a file already exists at `path`.
    pub fn create(path: impl Into<PathBuf>, password: &str) -> Result<Self, VaultError> {
        Self::create_with(path, password, KdfParams::DEFAULT)
    }

    /// Like [`Vault::create`] with explicit Argon2id parameters (must be ≥ [`KdfParams::MINIMUM`]).
    pub fn create_with(
        path: impl Into<PathBuf>,
        password: &str,
        kdf: KdfParams,
    ) -> Result<Self, VaultError> {
        let path = path.into();
        kdf.validate_for_new()?;
        let pw = kdf::normalise_new_password(password)?;

        let vault_key = Zeroizing::new(kdf::random::<KEY_LEN>()?);
        let slot = new_password_slot(&pw, &vault_key, kdf)?;
        let slots = vec![Slot::Password(slot)];

        let mut vault = Vault {
            path,
            envelope: Envelope {
                magic: MAGIC.to_owned(),
                version: VERSION,
                slots: slots.clone(),
                // Placeholder; replaced by the first write below.
                body: Body {
                    nonce: vec![0; NONCE_LEN],
                    ciphertext: vec![0; 16],
                },
            },
            unlocked: Some(Unlocked {
                vault_key,
                entries: Vec::new(),
                active: None,
                revision: 0,
                blobs: BTreeMap::new(),
            }),
            kdf_for_new: kdf,
        };
        let new_env = vault.write_state(&slots, None, 1, true)?;
        vault.envelope = new_env;
        if let Some(u) = vault.unlocked.as_mut() {
            u.revision = 1;
        }
        Ok(vault)
    }

    /// Opens an existing vault file. The vault starts **locked**; no password is needed to open.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let path = path.into();
        let bytes = fsutil::read_limited(&path)?;
        let envelope = Envelope::parse(&bytes)?;
        Ok(Vault {
            path,
            envelope,
            unlocked: None,
            kdf_for_new: KdfParams::DEFAULT,
        })
    }

    /// `true` if a file exists at `path`.
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Where the vault file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `true` while keys are decrypted in memory.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// Decrypts the vault with `password`.
    pub fn unlock(&mut self, password: &str) -> Result<(), VaultError> {
        if self.unlocked.is_some() {
            return Err(VaultError::AlreadyUnlocked);
        }
        let vault_key = self.unwrap_vault_key(password)?;
        let aad = body_aad(&self.envelope.slots);
        let plaintext = kdf::open(
            &vault_key,
            &self.envelope.body.nonce,
            &aad,
            &self.envelope.body.ciphertext,
        )?;
        let (meta, identities) = decode_body(&plaintext)?;
        let entries = meta
            .accounts
            .into_iter()
            .zip(identities)
            .map(|(stored, identity)| Entry { stored, identity })
            .collect();
        self.unlocked = Some(Unlocked {
            vault_key,
            entries,
            active: meta.active,
            revision: meta.revision,
            blobs: meta.blobs,
        });
        Ok(())
    }

    /// Wipes all decrypted material from memory. Idempotent.
    pub fn lock(&mut self) {
        self.unlocked = None; // Drop zeroises the vault key and every secret key.
    }

    /// Re-checks `password` against the vault (costs one Argon2id evaluation). Used for step-up
    /// authentication before sensitive operations.
    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        self.unwrap_vault_key(password).map(|_| ())
    }

    /// Changes the vault password and rotates the vault key.
    ///
    /// Copies of the vault file made *before* the change remain decryptable with the *old*
    /// password; this is inherent to any file-based vault (see `docs/SECURITY.md`).
    pub fn change_password(&mut self, old: &str, new: &str) -> Result<(), VaultError> {
        self.require_unlocked()?;
        self.verify_password(old)?;
        let pw = kdf::normalise_new_password(new)?;
        self.kdf_for_new.validate_for_new()?;

        let new_key = Zeroizing::new(kdf::random::<KEY_LEN>()?);
        let slot = new_password_slot(&pw, &new_key, self.kdf_for_new)?;
        let slots = vec![Slot::Password(slot)];
        let revision = self.next_revision()?;
        let env = self.write_state(&slots, Some(&new_key), revision, false)?;
        self.envelope = env;
        if let Some(u) = self.unlocked.as_mut() {
            u.vault_key = new_key;
            u.revision = revision;
        }
        Ok(())
    }

    /// Sets the Argon2id cost used by the next [`Vault::change_password`].
    pub fn set_kdf_for_new(&mut self, params: KdfParams) -> Result<(), VaultError> {
        params.validate_for_new()?;
        self.kdf_for_new = params;
        Ok(())
    }

    /// The Argon2id parameters protecting this vault.
    pub fn kdf_params(&self) -> Result<KdfParams, VaultError> {
        Ok(self.envelope.password_slot()?.kdf_params())
    }

    /// `true` if the vault was created with weaker parameters than [`KdfParams::DEFAULT`] and
    /// should be re-protected with [`Vault::change_password`].
    pub fn kdf_upgrade_recommended(&self) -> bool {
        self.kdf_params()
            .map(|p| {
                p.m_kib < KdfParams::DEFAULT.m_kib
                    || p.t_cost < KdfParams::DEFAULT.t_cost
                    || p.p_cost < KdfParams::DEFAULT.p_cost
            })
            .unwrap_or(false)
    }

    /// Warnings about file/directory permissions (Unix); empty when everything is private.
    pub fn permission_warnings(&self) -> Vec<String> {
        fsutil::permission_warnings(&self.path)
    }

    // ===== accounts ===================================================================

    /// Public information about every account, in insertion order.
    pub fn list_accounts(&self) -> Result<Vec<AccountMeta>, VaultError> {
        let u = self.require_unlocked()?;
        Ok(u.entries.iter().map(to_meta).collect())
    }

    /// The currently active account, if any.
    pub fn active_account(&self) -> Result<Option<AccountMeta>, VaultError> {
        let u = self.require_unlocked()?;
        Ok(u.active
            .and_then(|id| u.entries.iter().find(|e| e.stored.id == id))
            .map(to_meta))
    }

    /// Generates a new identity inside the vault. Its key has never existed outside the vault, so
    /// it is recorded as [`KeySecurity::Medium`].
    pub fn add_generated(&mut self, label: &str) -> Result<AccountMeta, VaultError> {
        self.add(label, Identity::generate(), KeySecurity::Medium)
    }

    /// Imports a secret key given as `nsec1…` or 64 hex characters. A key that was pasted as text
    /// has been handled insecurely by definition, so it is recorded as [`KeySecurity::Weak`].
    pub fn import_secret(&mut self, label: &str, secret: &str) -> Result<AccountMeta, VaultError> {
        let identity = Identity::from_secret_str(secret)?;
        self.add(label, identity, KeySecurity::Weak)
    }

    /// Imports a NIP-49 `ncryptsec1…` backup, keeping the key-security byte it carries.
    pub fn import_ncryptsec(
        &mut self,
        label: &str,
        ncryptsec: &str,
        password: &str,
    ) -> Result<AccountMeta, VaultError> {
        let (identity, security) =
            Identity::from_ncryptsec(ncryptsec, password, &Limits::default())?;
        self.add(label, identity, security)
    }

    /// Makes `id` the active account (persisted).
    pub fn set_active(&mut self, id: AccountId) -> Result<(), VaultError> {
        let u = self.require_unlocked()?;
        if !u.entries.iter().any(|e| e.stored.id == id) {
            return Err(VaultError::AccountNotFound);
        }
        let previous = u.active;
        self.unlocked_mut()?.active = Some(id);
        self.commit_or(|v| v.unlocked_mut().map(|u| u.active = previous))
    }

    /// Renames an account.
    pub fn set_label(&mut self, id: AccountId, label: &str) -> Result<(), VaultError> {
        let label = validate::label(label)?;
        let u = self.unlocked_mut()?;
        let entry = u
            .entries
            .iter_mut()
            .find(|e| e.stored.id == id)
            .ok_or(VaultError::AccountNotFound)?;
        let old = std::mem::replace(&mut entry.stored.label, label);
        self.commit_or(move |v| {
            if let Some(e) = v
                .unlocked_mut()?
                .entries
                .iter_mut()
                .find(|e| e.stored.id == id)
            {
                e.stored.label = old;
            }
            Ok(())
        })
    }

    /// Sets or clears an account's avatar.
    pub fn set_avatar(&mut self, id: AccountId, avatar: Option<Avatar>) -> Result<(), VaultError> {
        let new = match avatar {
            Some(a) => {
                validate::avatar(&a.mime, &a.data)?;
                Some(StoredAvatar {
                    mime: a.mime,
                    data: a.data,
                })
            }
            None => None,
        };
        let u = self.unlocked_mut()?;
        let entry = u
            .entries
            .iter_mut()
            .find(|e| e.stored.id == id)
            .ok_or(VaultError::AccountNotFound)?;
        let old = std::mem::replace(&mut entry.stored.avatar, new);
        self.commit_or(move |v| {
            if let Some(e) = v
                .unlocked_mut()?
                .entries
                .iter_mut()
                .find(|e| e.stored.id == id)
            {
                e.stored.avatar = old;
            }
            Ok(())
        })
    }

    /// The avatar of an account, if it has one.
    pub fn avatar(&self, id: AccountId) -> Result<Option<Avatar>, VaultError> {
        let u = self.require_unlocked()?;
        let e = u
            .entries
            .iter()
            .find(|e| e.stored.id == id)
            .ok_or(VaultError::AccountNotFound)?;
        Ok(e.stored.avatar.as_ref().map(|a| Avatar {
            mime: a.mime.clone(),
            data: a.data.clone(),
        }))
    }

    /// Permanently removes an account **and its key**. Callers (UI) must have obtained explicit
    /// confirmation, and should have offered a NIP-49 export first.
    pub fn remove_account(&mut self, id: AccountId) -> Result<(), VaultError> {
        let u = self.unlocked_mut()?;
        let pos = u
            .entries
            .iter()
            .position(|e| e.stored.id == id)
            .ok_or(VaultError::AccountNotFound)?;
        let removed = u.entries.remove(pos);
        let previous_active = u.active;
        if u.active == Some(id) {
            u.active = u.entries.first().map(|e| e.stored.id);
        }
        self.commit_or(move |v| {
            let u = v.unlocked_mut()?;
            u.entries.insert(pos.min(u.entries.len()), removed);
            u.active = previous_active;
            Ok(())
        })
    }

    // ===== application blobs (policy, settings) =======================================

    /// Reads a named application blob (e.g. the permission store). Blobs are encrypted and
    /// authenticated together with the accounts, so they cannot be forged without the password.
    pub fn blob(&self, name: &str) -> Result<Option<Vec<u8>>, VaultError> {
        let u = self.require_unlocked()?;
        Ok(u.blobs.get(name).map(|b| b.0.clone()))
    }

    /// Stores (or, with `None`, removes) a named application blob and persists the vault.
    pub fn set_blob(&mut self, name: &str, data: Option<&[u8]>) -> Result<(), VaultError> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_./-".contains(&b))
        {
            return Err(VaultError::InvalidBlob(
                "name must be 1-64 chars of [a-z0-9_./-]",
            ));
        }
        if data.is_some_and(|d| d.len() > MAX_BLOB_BYTES) {
            return Err(VaultError::InvalidBlob("blob too large"));
        }
        let u = self.unlocked_mut()?;
        if data.is_some() && !u.blobs.contains_key(name) && u.blobs.len() >= MAX_BLOBS {
            return Err(VaultError::InvalidBlob("too many blobs"));
        }
        let old = match data {
            Some(d) => u.blobs.insert(name.to_owned(), StoredBlob(d.to_vec())),
            None => u.blobs.remove(name),
        };
        let name = name.to_owned();
        self.commit_or(move |v| {
            let u = v.unlocked_mut()?;
            match old {
                Some(b) => u.blobs.insert(name, b),
                None => u.blobs.remove(&name),
            };
            Ok(())
        })
    }

    // ===== using keys (without exposing them) =========================================

    /// Runs `f` with the identity of account `id`. The reference cannot outlive the call.
    pub fn with_identity<R>(
        &self,
        id: AccountId,
        f: impl FnOnce(&Identity) -> R,
    ) -> Result<R, VaultError> {
        let u = self.require_unlocked()?;
        let e = u
            .entries
            .iter()
            .find(|e| e.stored.id == id)
            .ok_or(VaultError::AccountNotFound)?;
        Ok(f(&e.identity))
    }

    // ===== explicit, re-authenticated secret export ===================================

    /// Exports account `id` as a NIP-49 `ncryptsec1…` string protected by `export_password`.
    ///
    /// Requires the *vault* password again (step-up authentication): otherwise anyone with
    /// access to an unlocked session could export every key under a password of their choosing.
    pub fn export_ncryptsec(
        &self,
        id: AccountId,
        vault_password: &str,
        export_password: &str,
        log_n: u8,
    ) -> Result<String, VaultError> {
        let u = self.require_unlocked()?;
        self.verify_password(vault_password)?;
        let e = u
            .entries
            .iter()
            .find(|e| e.stored.id == id)
            .ok_or(VaultError::AccountNotFound)?;
        Ok(e.identity
            .export_ncryptsec(export_password, log_n, e.stored.key_security)?)
    }

    /// Reveals account `id`'s private key as `nsec1…`. Requires the vault password again.
    /// The UI must make the consequences explicit before calling this.
    pub fn reveal_nsec(
        &self,
        id: AccountId,
        vault_password: &str,
    ) -> Result<Zeroizing<String>, VaultError> {
        let u = self.require_unlocked()?;
        self.verify_password(vault_password)?;
        let e = u
            .entries
            .iter()
            .find(|e| e.stored.id == id)
            .ok_or(VaultError::AccountNotFound)?;
        Ok(e.identity.reveal_nsec()?)
    }

    // ===== backup and recovery ========================================================

    /// Writes an encrypted backup of the whole vault (all accounts) to `dest`.
    ///
    /// The backup is the vault file itself: it is protected by the vault password *at the time of
    /// the backup*. Refuses to overwrite an existing file. Needs no secret, because it reveals
    /// nothing a copy of the vault file would not.
    pub fn export_backup(&self, dest: &Path) -> Result<(), VaultError> {
        self.require_unlocked()?;
        let bytes = self.envelope.to_bytes()?;
        fsutil::write_atomic(dest, &bytes, true)
    }

    /// Restores a backup into a **new** vault file at `dest` after proving that `password` opens
    /// it. Refuses to overwrite an existing file. Returns the unlocked vault.
    pub fn restore_backup(
        backup: &Path,
        password: &str,
        dest: impl Into<PathBuf>,
    ) -> Result<Self, VaultError> {
        let dest = dest.into();
        let bytes = fsutil::read_limited(backup)?;
        let envelope = Envelope::parse(&bytes)?;
        let mut vault = Vault {
            path: dest.clone(),
            envelope,
            unlocked: None,
            kdf_for_new: KdfParams::DEFAULT,
        };
        vault.unlock(password)?; // nothing is written unless this succeeds
        fsutil::write_atomic(&dest, &vault.envelope.to_bytes()?, true)?;
        Ok(vault)
    }

    // ===== internals ==================================================================

    fn require_unlocked(&self) -> Result<&Unlocked, VaultError> {
        self.unlocked.as_ref().ok_or(VaultError::Locked)
    }

    fn unlocked_mut(&mut self) -> Result<&mut Unlocked, VaultError> {
        self.unlocked.as_mut().ok_or(VaultError::Locked)
    }

    fn next_revision(&self) -> Result<u64, VaultError> {
        Ok(self.require_unlocked()?.revision.saturating_add(1))
    }

    fn unwrap_vault_key(&self, password: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let pw = kdf::normalise(password);
        let slot = self.envelope.password_slot()?;
        let kek = kdf::derive_kek(&pw, &slot.kdf.salt, slot.kdf_params())?;
        let raw = kdf::open(&kek, &slot.nonce, &slot.aad(), &slot.wrapped_key)?;
        let key: [u8; KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Malformed("bad wrapped key"))?;
        Ok(Zeroizing::new(key))
    }

    fn add(
        &mut self,
        label: &str,
        identity: Identity,
        key_security: KeySecurity,
    ) -> Result<AccountMeta, VaultError> {
        let label = validate::label(label)?;
        let u = self.require_unlocked()?;
        if u.entries.len() >= MAX_ACCOUNTS {
            return Err(VaultError::TooManyAccounts(MAX_ACCOUNTS));
        }
        let pubkey_hex = identity.pubkey_hex();
        if u.entries.iter().any(|e| e.stored.pubkey_hex == pubkey_hex) {
            return Err(VaultError::DuplicateAccount);
        }
        let stored = StoredAccount {
            id: AccountId::generate().map_err(|_| VaultError::Rng)?,
            label,
            pubkey_hex,
            created_at: now_secs(),
            key_security,
            avatar: None,
        };
        let id = stored.id;
        let was_empty = u.entries.is_empty();
        let previous_active = u.active;

        let u = self.unlocked_mut()?;
        u.entries.push(Entry { stored, identity });
        if was_empty || u.active.is_none() {
            u.active = Some(id);
        }
        self.commit_or(move |v| {
            let u = v.unlocked_mut()?;
            u.entries.pop();
            u.active = previous_active;
            Ok(())
        })?;
        let u = self.require_unlocked()?;
        u.entries
            .last()
            .map(to_meta)
            .ok_or(VaultError::AccountNotFound)
    }

    /// Persists the current in-memory state; if that fails, runs `undo` so memory and disk agree.
    fn commit_or(
        &mut self,
        undo: impl FnOnce(&mut Self) -> Result<(), VaultError>,
    ) -> Result<(), VaultError> {
        let result = self.next_revision().and_then(|rev| {
            let slots = self.envelope.slots.clone();
            self.write_state(&slots, None, rev, false)
                .map(|env| (env, rev))
        });
        match result {
            Ok((env, rev)) => {
                self.envelope = env;
                self.unlocked_mut()?.revision = rev;
                Ok(())
            }
            Err(e) => {
                let _ = undo(self);
                Err(e)
            }
        }
    }

    /// Encrypts the current state under `key_override` (or the current vault key), writes it
    /// atomically and returns the envelope that was written. Does not touch `self.envelope`.
    fn write_state(
        &self,
        slots: &[Slot],
        key_override: Option<&Zeroizing<[u8; KEY_LEN]>>,
        revision: u64,
        must_not_exist: bool,
    ) -> Result<Envelope, VaultError> {
        let u = self.require_unlocked()?;
        let key = key_override.unwrap_or(&u.vault_key);
        let plaintext = encode_body(u, revision)?;
        let nonce = kdf::random::<NONCE_LEN>()?;
        let aad = body_aad(slots);
        let ciphertext = kdf::seal(key, &nonce, &aad, &plaintext)?;
        let envelope = Envelope {
            magic: MAGIC.to_owned(),
            version: VERSION,
            slots: slots.to_vec(),
            body: Body {
                nonce: nonce.to_vec(),
                ciphertext,
            },
        };
        fsutil::write_atomic(&self.path, &envelope.to_bytes()?, must_not_exist)?;
        Ok(envelope)
    }
}

// ---- helpers --------------------------------------------------------------------------

fn new_password_slot(
    password: &str,
    vault_key: &Zeroizing<[u8; KEY_LEN]>,
    params: KdfParams,
) -> Result<PasswordSlot, VaultError> {
    let salt = kdf::random::<SALT_LEN>()?;
    let kek = kdf::derive_kek(password, &salt, params)?;
    let nonce = kdf::random::<NONCE_LEN>()?;
    let mut slot = PasswordSlot {
        kdf: format::KdfDesc {
            alg: KDF_ALG.to_owned(),
            v: 0x13,
            m_kib: params.m_kib,
            t: params.t_cost,
            p: params.p_cost,
            salt: salt.to_vec(),
        },
        nonce: nonce.to_vec(),
        wrapped_key: Vec::new(),
    };
    slot.wrapped_key = kdf::seal(&kek, &nonce, &slot.aad(), vault_key.as_ref())?;
    Ok(slot)
}

fn to_meta(e: &Entry) -> AccountMeta {
    AccountMeta {
        id: e.stored.id,
        label: e.stored.label.clone(),
        pubkey_hex: e.stored.pubkey_hex.clone(),
        npub: e.identity.npub(),
        created_at: e.stored.created_at,
        key_security: e.stored.key_security,
        has_avatar: e.stored.avatar.is_some(),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn encode_body(u: &Unlocked, revision: u64) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let meta = BodyMeta {
        revision,
        active: u.active,
        accounts: u.entries.iter().map(|e| e.stored.clone()).collect(),
        blobs: u.blobs.clone(),
    };
    let meta_json = serde_json::to_vec(&meta)
        .map_err(|_| VaultError::Malformed("cannot serialise accounts"))?;
    let meta_len =
        u32::try_from(meta_json.len()).map_err(|_| VaultError::Malformed("metadata too large"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        5 + meta_json.len() + 32 * u.entries.len(),
    ));
    out.push(BODY_FORMAT);
    out.extend_from_slice(&meta_len.to_le_bytes());
    out.extend_from_slice(&meta_json);
    for e in &u.entries {
        out.extend_from_slice(e.identity.secret_bytes().as_ref());
    }
    Ok(out)
}

fn decode_body(plain: &[u8]) -> Result<(BodyMeta, Vec<Identity>), VaultError> {
    let bad = VaultError::Malformed("bad body layout");
    let (&fmt, rest) = plain
        .split_first()
        .ok_or(VaultError::Malformed("bad body layout"))?;
    if fmt != BODY_FORMAT {
        return Err(VaultError::Malformed("unsupported body format"));
    }
    let (len_bytes, rest) = rest
        .split_at_checked(4)
        .ok_or(VaultError::Malformed("bad body layout"))?;
    let meta_len = u32::from_le_bytes(
        len_bytes
            .try_into()
            .map_err(|_| VaultError::Malformed("bad body layout"))?,
    ) as usize;
    let (meta_json, secrets) = rest.split_at_checked(meta_len).ok_or(bad)?;
    let meta: BodyMeta = serde_json::from_slice(meta_json)
        .map_err(|_| VaultError::Malformed("bad account metadata"))?;

    if meta.accounts.len() > MAX_ACCOUNTS {
        return Err(VaultError::Malformed("too many accounts"));
    }
    if secrets.len() != meta.accounts.len() * KEY_LEN {
        return Err(VaultError::Malformed("account/key count mismatch"));
    }
    let mut identities = Vec::with_capacity(meta.accounts.len());
    for (acc, chunk) in meta.accounts.iter().zip(secrets.chunks_exact(KEY_LEN)) {
        let arr: [u8; KEY_LEN] = chunk
            .try_into()
            .map_err(|_| VaultError::Malformed("bad key length"))?;
        let arr = Zeroizing::new(arr);
        let identity = Identity::from_secret_bytes(&arr)?;
        if identity.pubkey_hex() != acc.pubkey_hex {
            return Err(VaultError::Malformed(
                "account public key does not match its key",
            ));
        }
        identities.push(identity);
    }
    // Uniqueness invariants.
    for (i, a) in meta.accounts.iter().enumerate() {
        if meta
            .accounts
            .iter()
            .skip(i + 1)
            .any(|b| b.id == a.id || b.pubkey_hex == a.pubkey_hex)
        {
            return Err(VaultError::Malformed("duplicate account"));
        }
    }
    if let Some(active) = meta.active {
        if !meta.accounts.iter().any(|a| a.id == active) {
            return Err(VaultError::Malformed("active account does not exist"));
        }
    }
    Ok((meta, identities))
}
