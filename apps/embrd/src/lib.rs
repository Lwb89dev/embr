//! The Embr signer daemon.
//!
//! `embrd` is the only process that ever holds decrypted key material. It runs as the user, serves
//! two Unix-domain sockets and does nothing else:
//!
//! * the **client API** (`signer.sock`, `docs/LOCAL_SIGNER_API.md`): authenticated, per-client
//!   grants, approval prompts;
//! * the **control channel** (`control.sock`): the GUI/CLI unlock the vault, manage accounts and
//!   answer approval prompts. A client of the first socket cannot use the second.
//!
//! Endpoints are Unix-domain sockets (Linux/macOS) or user-only named pipes (Windows).
#![allow(clippy::print_stderr, unreachable_pub)]

mod audit;
mod canonical;
mod client_api;
mod control_api;
mod nip46;
mod server;
mod state;

pub use server::{DaemonError, DaemonHandle, start};
pub use state::{DaemonConfig, DaemonLimits, Shared};

/// Logs a line to stderr (journald/terminal). Never pass secrets or message content.
pub fn log(msg: &str) {
    eprintln!("[embrd] {msg}");
}
