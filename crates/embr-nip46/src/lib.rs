//! NIP-46 remote signing for Embr.
//!
//! * [`uri`] — `bunker://` and `nostrconnect://` parsing/rendering with strict validation.
//! * [`protocol`] — JSON-RPC over NIP-44-encrypted kind-24133 events; the signer uses a **transport
//!   key distinct from the user's key**.
//! * [`relay`] — a small event-driven relay client (TLS via rustls, NIP-42 AUTH, reconnection).
//! * [`service`] — the signer service with replay/freshness/rate-limit defences; authorisation is
//!   delegated to a [`service::Handler`].
//!
//! Nothing in this crate runs, and no network connection is made, until a [`service::Service`] is
//! created *and* relays are set — i.e. until the user enabled remote signing and configured relays.

pub mod protocol;
pub mod relay;
pub mod service;
pub mod uri;

#[cfg(feature = "testing")]
pub mod testing;
