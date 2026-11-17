//! OS glue for the Embr signer.
//!
//! Everything that touches the operating system lives here so the core crates stay portable and
//! free of `unsafe`. This crate also avoids `unsafe` by using `rustix`'s safe wrappers; if a future
//! platform feature requires it, the `unsafe` block must be justified in place.
//!
//! Status: Unix (Linux/macOS) implemented and tested on Linux. Windows: named-pipe endpoints with a
//! user-only DACL are implemented in [`windows`] and exercised by the Windows CI job only (not by the
//! author's machine).

pub mod harden;
pub mod instance;
pub mod paths;
pub mod peer;
#[cfg(windows)]
pub mod windows;
