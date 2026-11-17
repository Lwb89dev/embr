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
//! No network I/O happens in this crate. Windows is not supported yet (named pipes are the next
//! step of Milestone 3).
#![allow(clippy::print_stderr, unreachable_pub)]

#[cfg(unix)]
mod audit;
#[cfg(unix)]
mod canonical;
#[cfg(unix)]
mod client_api;
#[cfg(unix)]
mod control_api;
#[cfg(unix)]
mod nip46;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod state;

#[cfg(unix)]
pub use server::{DaemonError, DaemonHandle, start};
#[cfg(unix)]
pub use state::{DaemonConfig, DaemonLimits, Shared};

/// Logs a line to stderr (journald/terminal). Never pass secrets or message content.
pub fn log(msg: &str) {
    eprintln!("[embrd] {msg}");
}
