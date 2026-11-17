//! Structured protocol errors.

use serde::{Deserialize, Serialize};

/// Error codes. 1–5 and 10 mirror the codes of Amber Desktop's local socket so adapters are easy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    /// Not JSON / wrong shape / duplicate id / unknown field.
    InvalidRequest = 1,
    /// Method not supported.
    UnsupportedMethod = 2,
    /// Bad parameters (bad event, key, limit exceeded).
    InvalidParams = 3,
    /// Unknown account, or not granted to this client.
    AccountNotFound = 4,
    /// Rejected by the user or by a stored deny rule.
    Denied = 5,
    /// The vault is locked.
    VaultLocked = 6,
    /// Timed out waiting for the user.
    Expired = 7,
    /// Cancelled (by the client, a lock, a disconnect or an account removal).
    Cancelled = 8,
    /// Too many requests.
    RateLimited = 9,
    /// Internal error.
    Internal = 10,
    /// A line or field was too large.
    PayloadTooLarge = 11,
    /// Missing or invalid handshake proof.
    Unauthenticated = 12,
    /// The client key is unknown to the signer.
    NotPaired = 13,
    /// The daemon is busy with an exclusive operation; retry.
    Busy = 14,
}

impl ErrorCode {
    /// Stable machine-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::UnsupportedMethod => "unsupported_method",
            ErrorCode::InvalidParams => "invalid_params",
            ErrorCode::AccountNotFound => "account_not_found",
            ErrorCode::Denied => "denied",
            ErrorCode::VaultLocked => "vault_locked",
            ErrorCode::Expired => "expired",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::Internal => "internal",
            ErrorCode::PayloadTooLarge => "payload_too_large",
            ErrorCode::Unauthenticated => "unauthenticated",
            ErrorCode::NotPaired => "not_paired",
            ErrorCode::Busy => "busy",
        }
    }

    /// Parses a numeric code.
    pub fn from_u16(n: u16) -> Option<Self> {
        Some(match n {
            1 => ErrorCode::InvalidRequest,
            2 => ErrorCode::UnsupportedMethod,
            3 => ErrorCode::InvalidParams,
            4 => ErrorCode::AccountNotFound,
            5 => ErrorCode::Denied,
            6 => ErrorCode::VaultLocked,
            7 => ErrorCode::Expired,
            8 => ErrorCode::Cancelled,
            9 => ErrorCode::RateLimited,
            10 => ErrorCode::Internal,
            11 => ErrorCode::PayloadTooLarge,
            12 => ErrorCode::Unauthenticated,
            13 => ErrorCode::NotPaired,
            14 => ErrorCode::Busy,
            _ => return None,
        })
    }
}

/// The `error` object of a response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{name} ({code}): {message}")]
pub struct RpcError {
    /// Numeric code ([`ErrorCode`]).
    pub code: u16,
    /// Machine-readable name.
    pub name: String,
    /// Human-readable message (never contains secrets).
    pub message: String,
    /// Optional extra data, e.g. `{"retry_after_ms": 1000}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RpcError {
    /// Builds an error.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as u16,
            name: code.name().to_owned(),
            message: message.into(),
            data: None,
        }
    }

    /// Adds `data`.
    #[must_use]
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// The typed code, if known.
    pub fn error_code(&self) -> Option<ErrorCode> {
        ErrorCode::from_u16(self.code)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn codes_roundtrip_and_have_unique_names() {
        let mut names = std::collections::BTreeSet::new();
        for n in 1..=14u16 {
            let c = ErrorCode::from_u16(n).unwrap_or_else(|| panic!("code {n} missing"));
            assert_eq!(c as u16, n);
            assert!(names.insert(c.name()), "duplicate name {}", c.name());
        }
        assert!(ErrorCode::from_u16(0).is_none());
        assert!(ErrorCode::from_u16(15).is_none());
    }

    #[test]
    fn amber_compatible_numbers() {
        assert_eq!(ErrorCode::InvalidRequest as u16, 1);
        assert_eq!(ErrorCode::UnsupportedMethod as u16, 2);
        assert_eq!(ErrorCode::InvalidParams as u16, 3);
        assert_eq!(ErrorCode::AccountNotFound as u16, 4);
        assert_eq!(ErrorCode::Denied as u16, 5);
        assert_eq!(ErrorCode::Internal as u16, 10);
    }
}
