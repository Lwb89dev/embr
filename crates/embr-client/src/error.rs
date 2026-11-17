//! Client errors.

use embr_ipc::codec::CodecError;
use embr_ipc::{ErrorCode, RpcError};

/// Errors returned by the SDK.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The signer is not running or not reachable.
    #[error("cannot connect to the signer: {0}")]
    Connect(std::io::Error),
    /// I/O error on an established connection.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Framing error.
    #[error("protocol framing error: {0}")]
    Codec(#[from] CodecError),
    /// The peer violated the protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The signer answered with an error.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// Local cryptography failed (e.g. building the handshake proof).
    #[error("local crypto error: {0}")]
    Crypto(String),
    /// This platform has no transport yet.
    #[error("this platform is not supported yet")]
    Unsupported,
}

impl ClientError {
    /// The signer's error code, if this is an [`ClientError::Rpc`].
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Rpc(e) => e.error_code(),
            _ => None,
        }
    }
}
