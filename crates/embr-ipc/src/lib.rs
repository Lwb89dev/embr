//! Wire protocol of the Embr local signer API (`docs/LOCAL_SIGNER_API.md`) and of the privileged
//! control channel used by the GUI and CLI.
//!
//! This crate contains **types, framing and the client-authentication proof only** — no sockets,
//! no OS calls, no policy. It is shared by the daemon, the client SDK and the CLI.

pub mod auth;
pub mod codec;
pub mod control;
mod error;
mod wire;

pub use error::{ErrorCode, RpcError};
pub use wire::*;

/// Version of the local protocol implemented by this crate.
pub const PROTOCOL_VERSION: u32 = 1;
/// Maximum size of one JSON line (request, response or handshake), in bytes.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Maximum length of a request id.
pub const MAX_ID_LEN: usize = 64;
/// How long a new connection may take to complete the handshake.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
/// Default and maximum per-request timeout the client may ask for, in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// Upper bound for `timeout_ms`.
pub const MAX_TIMEOUT_MS: u64 = 600_000;
