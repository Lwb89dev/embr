//! Metadata-only audit records. They never contain keys, plaintexts, ciphertexts, signatures or
//! event content — only *who asked for what, and what happened*.

use embr_core::{AccountId, Operation, Pubkey32};
use serde::{Deserialize, Serialize};

/// What happened to a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Executed because an existing grant covered it.
    AllowedByGrant,
    /// Executed after the user approved it.
    AllowedByUser,
    /// Refused because of a stored deny rule.
    DeniedByGrant,
    /// The user rejected it.
    DeniedByUser,
    /// Refused: client not paired / blocked / account not granted.
    Refused,
    /// Timed out waiting for the user.
    Expired,
    /// Withdrawn by the client, or resolved by a lock/disconnect.
    Cancelled,
    /// Dropped by a rate limit.
    RateLimited,
    /// Pairing approved.
    Paired,
    /// A permission was revoked.
    Revoked,
    /// Vault locked/unlocked or another administrative event.
    Admin,
}

/// One line of the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unix seconds.
    pub ts: u64,
    /// Transport: `"local"`, `"nip46"` or `"control"`.
    pub via: String,
    /// The requesting client, if any.
    pub client: Option<Pubkey32>,
    /// The client's self-declared label, sanitised (untrusted).
    pub client_name: Option<String>,
    /// Account involved.
    pub account: Option<AccountId>,
    /// Operation (`"pair"` for pairing).
    pub action: String,
    /// Event kind, for signing.
    pub kind: Option<u16>,
    /// Result.
    pub outcome: AuditOutcome,
    /// Id of the grant that decided it, if any.
    pub grant: Option<u64>,
    /// Short non-sensitive note.
    pub note: Option<String>,
}

impl AuditRecord {
    /// A record skeleton for an operation request.
    pub fn for_operation(
        ts: u64,
        via: &str,
        client: Pubkey32,
        op: Operation,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            ts,
            via: via.to_owned(),
            client: Some(client),
            client_name: None,
            account: None,
            action: op.as_str().to_owned(),
            kind: None,
            outcome,
            grant: None,
            note: None,
        }
    }
}
