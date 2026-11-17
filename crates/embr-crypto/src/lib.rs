//! Nostr cryptographic operations for the Embr signer.
//!
//! This crate is a **thin, validated wrapper** over the maintained [`rust-nostr`] implementation.
//! It contains no cryptographic primitives of its own: Schnorr/BIP-340 signing, NIP-44, NIP-04,
//! NIP-49 and NIP-19 are all delegated to the `nostr` crate (and, through it, to
//! `secp256k1`, `chacha20`, `scrypt`, ...). What this crate adds is:
//!
//! * a single type, [`Identity`], that owns secret key material and never exposes it by accident
//!   (no `Clone`, no `Display`, redacted `Debug`, zeroised on drop);
//! * strict validation of everything that crosses a trust boundary – event templates, peer public
//!   keys, ciphertext sizes – with explicit, configurable [`Limits`];
//! * guarantees that matter for a *signer*: a template can never make the signer sign for a
//!   different public key, and a client-supplied `id`/`sig` is never trusted.
//!
//! [`rust-nostr`]: https://github.com/rust-nostr/nostr

mod error;
mod identity;
mod keys;
mod template;

pub use error::CryptoError;
pub use identity::{Identity, MAX_EXPORT_LOG_N, MIN_EXPORT_LOG_N};
pub use keys::{encode_npub, parse_public_key};
pub use template::{EventTemplate, Limits};

/// Re-exported rust-nostr types that appear in this crate's public API.
pub use nostr::event::Event;
pub use nostr::key::PublicKey;
