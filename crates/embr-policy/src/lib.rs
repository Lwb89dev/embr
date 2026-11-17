//! Authorization engine for the Embr signer.
//!
//! Pure logic: no I/O, no clock (time is passed in), no secrets. Every transport — the local
//! IPC, NIP-46 — funnels requests through the same [`Engine`], so there is exactly one place
//! where "may this client do this?" is decided (the principle Amber's architecture document
//! recommends and its own desktop code base struggles to keep).
//!
//! ## Model
//! * A [`ClientRecord`] is a *paired* client (identified by its public key) bound to one or more
//!   accounts. Unpaired or blocked clients can do nothing.
//! * A [`Grant`] says *allow* or *deny* for one `(client, account, operation, kind, peer)` scope,
//!   with an [`Expiry`] and an optional use count.
//! * [`Engine::evaluate`] is **default-deny**: with no matching grant the verdict is
//!   [`Verdict::Ask`] (never "allow"); a matching *deny* always beats an *allow*.
//! * [`Engine::decide`] turns the user's [`Choice`] into grants, **refusing** choices that are
//!   too broad for the operation (see [`Engine::validate_choice`]).
//!
//! Persistent state ([`Persisted`]) is stored inside the encrypted vault, so it cannot be forged
//! without the vault password. Session and one-shot grants are never persisted.

mod audit;
mod engine;
mod rate;

pub use audit::{AuditOutcome, AuditRecord};
pub use engine::{
    Choice, ClientRecord, Decision, Effect, Engine, Expiry, Grant, GrantId, KindScope,
    MAX_BROAD_EXPIRY_SECS, MAX_CLIENTS, MAX_GRANTS, MAX_UNSCOPED_DECRYPT_SECS, Persisted,
    PolicyError, Request, SENSITIVE_KINDS, Scope, SessionId, Verdict,
};
pub use rate::RateLimiter;
