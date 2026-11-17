//! The privileged **control channel**: the API the GUI and CLI use to unlock the vault, manage
//! accounts, answer approval prompts and inspect permissions.
//!
//! It is a different endpoint with a different credential than the client API: a client of the
//! signer API cannot use it, so it cannot approve its own requests. Framing is the same
//! (JSON lines) and requests/responses reuse [`crate::Request`] / [`crate::Response`].
//!
//! Authentication: `unlock` / `create_vault` / `auth` with the **vault password** returns a
//! random control `token` that the GUI keeps in memory only; a reconnecting GUI presents it with
//! `auth {token}`. Tokens die when the vault locks. Only `status`, `unlock`, `create_vault` and
//! `auth` work before authentication.

use embr_core::{AccountId, AccountMeta, Pubkey32};
use embr_policy::{ClientRecord, Grant, KindScope};
use serde::{Deserialize, Serialize};

/// Version of the control protocol.
pub const CONTROL_PROTOCOL: u32 = 1;

/// Methods usable before authentication.
pub const UNAUTHENTICATED_METHODS: [&str; 4] = ["status", "unlock", "create_vault", "auth"];

/// Whether a vault file exists and whether it is open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    /// No vault yet: `create_vault` first.
    Missing,
    /// Present and locked.
    Locked,
    /// Present and unlocked.
    Unlocked,
}

/// Daemon status (readable without authentication; contains no account data).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    /// Daemon version.
    pub version: String,
    /// Vault state.
    pub vault: VaultState,
    /// Number of pending approval requests.
    pub pending: usize,
    /// Configured idle auto-lock timeout (0 = never).
    pub lock_timeout_secs: u64,
    /// Seconds until the idle auto-lock fires, if unlocked and a timeout is set.
    pub locks_in_secs: Option<u64>,
    /// Whether NIP-46 remote signing is enabled (it is off by default).
    pub remote_signing_enabled: bool,
}

/// First line sent on a control connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlHello {
    /// Control protocol version.
    pub embr_control: u32,
    /// Current status.
    pub status: StatusView,
}

/// User-configurable settings (stored encrypted inside the vault).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Idle auto-lock in seconds; 0 disables it. Otherwise 30..=86 400.
    pub lock_timeout_secs: u64,
    /// Show desktop notifications for approval requests.
    pub notifications: bool,
    /// NIP-46 remote signing (off by default; nothing connects to relays while false).
    pub remote_signing_enabled: bool,
    /// Relays used for NIP-46 (`wss://…`, or `ws://` to loopback). Empty by default: with no relays
    /// configured nothing connects even if remote signing is enabled.
    #[serde(default)]
    pub relays: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lock_timeout_secs: 15 * 60,
            notifications: true,
            remote_signing_enabled: false,
            relays: Vec::new(),
        }
    }
}

impl Settings {
    /// Validates user-supplied settings.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.lock_timeout_secs != 0 && !(30..=86_400).contains(&self.lock_timeout_secs) {
            return Err("lock timeout must be 0 (never) or between 30 s and 24 h");
        }
        if self.relays.len() > 8 || self.relays.iter().any(|r| r.len() > 256) {
            return Err("at most 8 relays, each at most 256 characters");
        }
        Ok(())
    }
}

/// What the OS told us about the peer process. **Untrusted hints for the prompt.**
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHint {
    /// Process id at connection time, if the OS reported one.
    pub pid: Option<i32>,
    /// User id.
    pub uid: u32,
    /// Executable path as resolved by the daemon, if readable. Can be spoofed by `exec`.
    pub exe: Option<String>,
}

/// Who is asking, as shown to the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdent {
    /// The client's real identity.
    pub pubkey: Pubkey32,
    /// Self-declared label, sanitised. Always unverified.
    pub name: String,
    /// Process hints (unverified).
    pub peer: Option<PeerHint>,
    /// Transport: `"local"` or `"nip46"`.
    pub via: String,
}

/// A safe preview of an event to be signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPreview {
    /// Event kind.
    pub kind: u16,
    /// Sanitised, truncated content.
    pub content: String,
    /// Real content length in bytes.
    pub content_len: usize,
    /// Sanitised tags (first 50).
    pub tags: Vec<Vec<String>>,
    /// Real number of tags.
    pub tags_total: usize,
    /// Requested creation time, if given.
    pub created_at: Option<u64>,
    /// `true` for DM-related kinds (4, 13, 14, 1059).
    pub sensitive: bool,
}

/// Kind of approval being requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    /// A new client asks to be paired.
    Pair,
    /// A paired client asks for an operation.
    Operation,
}

/// An approval request, as shown in the UI. This is the **stored canonical copy**: what is
/// displayed here is exactly what will be executed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingView {
    /// Daemon-assigned id.
    pub id: u64,
    /// Digest of the canonical request; must be echoed in the decision.
    pub digest: String,
    /// Pairing or operation.
    pub kind: PendingKind,
    /// Requesting client.
    pub client: ClientIdent,
    /// Target account (for pairing: the client's requested/default account, if any).
    pub account: Option<AccountMeta>,
    /// Operation name (`None` for pairing).
    pub operation: Option<String>,
    /// NIP-04 operation: show as legacy.
    pub legacy: bool,
    /// The operation returns plaintext of private data to the client.
    pub reveals_plaintext: bool,
    /// Event preview (sign requests).
    pub event: Option<EventPreview>,
    /// Peer public key (encrypt/decrypt).
    pub peer: Option<Pubkey32>,
    /// Sanitised preview of the plaintext to encrypt.
    pub text_preview: Option<String>,
    /// Size of the payload in bytes (ciphertext or plaintext).
    pub payload_len: Option<usize>,
    /// Permissions the client asked for at pairing (a wish, not a grant).
    pub requested_permissions: Vec<String>,
    /// Creation time.
    pub created_at: u64,
    /// When the request expires.
    pub expires_at: u64,
}

/// Scope of a remembered decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeWire {
    /// Kinds covered.
    pub kind: KindScope,
    /// Restrict to one peer.
    #[serde(default)]
    pub peer: Option<Pubkey32>,
    /// Limit the number of uses.
    #[serde(default)]
    pub uses: Option<u32>,
}

/// The user's decision.
///
/// Serialised as an internally tagged object (`{"choice":"allow_until","until":123}`). It is
/// *deserialised* through [`DecisionRaw`] because serde's `deny_unknown_fields` is not enforced for
/// unit variants of internally tagged enums, and we reject unknown fields everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "choice", rename_all = "snake_case", try_from = "DecisionRaw")]
pub enum DecisionWire {
    /// Allow this request only.
    AllowOnce,
    /// Allow matching requests for the client's session.
    AllowSession,
    /// Allow matching requests until `until` (Unix seconds).
    AllowUntil {
        /// Expiry.
        until: u64,
    },
    /// Allow matching requests until revoked.
    AllowPersistent,
    /// Reject this request only.
    RejectOnce,
    /// Reject matching requests from now on.
    AlwaysReject,
    /// Pairing: approve and bind the client to `account`.
    Pair {
        /// Account the client may use.
        account: AccountId,
    },
    /// Pairing: refuse and block this client key.
    BlockClient,
}

/// Strict intermediate form of [`DecisionWire`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRaw {
    choice: String,
    until: Option<u64>,
    account: Option<AccountId>,
}

impl TryFrom<DecisionRaw> for DecisionWire {
    type Error = String;

    fn try_from(r: DecisionRaw) -> Result<Self, String> {
        let extra = |what: &str| format!("field `{what}` is not valid for choice `{}`", r.choice);
        let d = match r.choice.as_str() {
            "allow_once" => DecisionWire::AllowOnce,
            "allow_session" => DecisionWire::AllowSession,
            "allow_persistent" => DecisionWire::AllowPersistent,
            "reject_once" => DecisionWire::RejectOnce,
            "always_reject" => DecisionWire::AlwaysReject,
            "block_client" => DecisionWire::BlockClient,
            "allow_until" => DecisionWire::AllowUntil {
                until: r.until.ok_or("`until` is required")?,
            },
            "pair" => DecisionWire::Pair {
                account: r.account.ok_or("`account` is required")?,
            },
            other => return Err(format!("unknown choice `{other}`")),
        };
        if r.until.is_some() && !matches!(d, DecisionWire::AllowUntil { .. }) {
            return Err(extra("until"));
        }
        if r.account.is_some() && !matches!(d, DecisionWire::Pair { .. }) {
            return Err(extra("account"));
        }
        Ok(d)
    }
}

// ---- parameters of control methods -----------------------------------------------------

macro_rules! params {
    ($(#[$m:meta])* $name:ident { $($(#[$fm:meta])* $f:ident : $t:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $($(#[$fm])* pub $f: $t),* }
    };
}

params!(
    /// `unlock`, `create_vault`.
    PasswordParams {
        /// Vault password.
        password: String,
    }
);
params!(
    /// `auth`.
    TokenParams {
        /// Control token.
        token: String,
    }
);
params!(
    /// `change_password`.
    ChangePasswordParams {
        /// Current password.
        old: String,
        /// New password.
        new: String,
    }
);
params!(
    /// `export_backup`.
    BackupParams {
        /// Destination path (must not exist).
        dest: String,
    }
);
params!(
    /// `add_generated`.
    AddGeneratedParams {
        /// Label.
        label: String,
    }
);
params!(
    /// `import_secret`.
    ImportSecretParams {
        /// Label.
        label: String,
        /// `nsec1…` or 64 hex.
        secret: String,
    }
);
params!(
    /// `import_ncryptsec`.
    ImportNcryptsecParams {
        /// Label.
        label: String,
        /// `ncryptsec1…`.
        ncryptsec: String,
        /// Its password.
        password: String,
    }
);
params!(
    /// Methods taking an account id.
    AccountIdParams {
        /// Account id.
        id: AccountId,
    }
);
params!(
    /// `set_label`.
    SetLabelParams {
        /// Account id.
        id: AccountId,
        /// New label.
        label: String,
    }
);
params!(
    /// `remove_account`.
    RemoveAccountParams {
        /// Account id.
        id: AccountId,
        /// Must be `true`.
        confirm: bool,
    }
);
params!(
    /// `export_ncryptsec`.
    ExportNcryptsecParams {
        /// Account id.
        id: AccountId,
        /// Vault password (step-up authentication).
        vault_password: String,
        /// Password protecting the export.
        export_password: String,
        /// scrypt cost (16..=20).
        log_n: u8,
    }
);
params!(
    /// `reveal_nsec`.
    RevealNsecParams {
        /// Account id.
        id: AccountId,
        /// Vault password (step-up authentication).
        vault_password: String,
    }
);
params!(
    /// `revoke_client`, `block_client`.
    ClientKeyParams {
        /// Client public key.
        key: Pubkey32,
    }
);
params!(
    /// `revoke_grant`.
    GrantIdParams {
        /// Grant id.
        id: u64,
    }
);
params!(
    /// `recent_log`.
    LogParams {
        /// Maximum number of records.
        limit: usize,
    }
);

params!(
    /// `nip46_bunker`.
    Nip46BunkerParams {
        /// Account the connection is for.
        account: AccountId,
    }
);
params!(
    /// `nip46_connect`.
    Nip46ConnectParams {
        /// A `nostrconnect://` URI created by a client.
        uri: String,
        /// Account the client will be bound to.
        account: AccountId,
    }
);

/// One relay's connection state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayView {
    /// URL.
    pub url: String,
    /// `connecting`, `connected` or `failed`.
    pub state: String,
    /// Failure reason, if any.
    pub detail: Option<String>,
}

/// A transport key of the NIP-46 signer (public part only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerView {
    /// Account it serves.
    pub account: AccountId,
    /// Transport public key (the `bunker://` pubkey) — **not** the user's key.
    pub transport_pubkey: Pubkey32,
}

/// Result of `nip46_status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46Status {
    /// Remote signing enabled in the settings.
    pub enabled: bool,
    /// The relay service is running (enabled, unlocked, relays configured).
    pub running: bool,
    /// Relays.
    pub relays: Vec<RelayView>,
    /// Transport keys.
    pub signers: Vec<SignerView>,
}

/// `decide`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideParams {
    /// Pending request id.
    pub id: u64,
    /// Digest copied from the [`PendingView`] the user looked at.
    pub digest: String,
    /// The decision.
    pub decision: DecisionWire,
    /// Scope of a remembered decision; defaults to the request's exact kind and peer.
    #[serde(default)]
    pub scope: Option<ScopeWire>,
}

/// Result of `list_clients`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientView {
    /// The stored record.
    #[serde(flatten)]
    pub record: ClientRecord,
    /// Number of stored grants for this client.
    pub grants: usize,
    /// Number of currently open sessions.
    pub connected: usize,
}

/// Result of `list_grants`.
pub type GrantView = Grant;

/// Asynchronous notifications on a control connection after `subscribe`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ControlEvent {
    /// A new approval request is waiting.
    PendingAdded {
        /// The request.
        request: Box<PendingView>,
    },
    /// A request was resolved or withdrawn.
    PendingRemoved {
        /// Request id.
        id: u64,
        /// `approved`, `rejected`, `expired`, `cancelled`.
        reason: String,
    },
    /// The vault was locked.
    Locked,
    /// The vault was unlocked.
    Unlocked,
    /// Clients or grants changed.
    ClientsChanged,
    /// Accounts changed.
    AccountsChanged,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decisions_use_a_tagged_wire_form() {
        let d: DecisionWire =
            serde_json::from_str(r#"{"choice":"allow_until","until":123}"#).unwrap();
        assert_eq!(d, DecisionWire::AllowUntil { until: 123 });
        assert!(serde_json::from_str::<DecisionWire>(r#"{"choice":"allow_forever"}"#).is_err());
        assert!(serde_json::from_str::<DecisionWire>(r#"{"choice":"allow_once","x":1}"#).is_err());
        assert!(
            serde_json::from_str::<DecisionWire>(r#"{"choice":"allow_once","until":5}"#).is_err()
        );
        assert!(serde_json::from_str::<DecisionWire>(r#"{"choice":"allow_until"}"#).is_err());
        assert!(serde_json::from_str::<DecisionWire>(r#"{"choice":"pair"}"#).is_err());
        assert_eq!(
            serde_json::to_string(&DecisionWire::AlwaysReject).unwrap(),
            r#"{"choice":"always_reject"}"#
        );
    }

    #[test]
    fn settings_validation() {
        assert!(Settings::default().validate().is_ok());
        for secs in [0, 30, 900, 86_400] {
            assert!(
                Settings {
                    lock_timeout_secs: secs,
                    ..Settings::default()
                }
                .validate()
                .is_ok(),
                "{secs}"
            );
        }
        for secs in [1, 29, 86_401] {
            assert!(
                Settings {
                    lock_timeout_secs: secs,
                    ..Settings::default()
                }
                .validate()
                .is_err(),
                "{secs}"
            );
        }
        assert!(
            !Settings::default().remote_signing_enabled,
            "remote signing must be off by default"
        );
    }

    #[test]
    fn events_are_tagged() {
        let s = serde_json::to_string(&ControlEvent::Locked).unwrap();
        assert_eq!(s, r#"{"event":"locked"}"#);
    }
}
