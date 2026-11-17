//! Blocking client SDK for the Embr local signer.
//!
//! ```no_run
//! use embr_client::{keyfile, ConnectOptions, SignerClient};
//!
//! // 1. Your app's own client key (an ordinary Nostr key pair; never the user's key).
//! let identity = keyfile::load_or_create("/home/me/.config/myapp/embr-client.key")?;
//! // 2. Connect and authenticate (proof of possession of that key).
//! let mut signer = SignerClient::connect(&identity, ConnectOptions::new("MyApp"))?;
//! // 3. Log in: the first time, the user approves MyApp inside Embr.
//! let pubkey = signer.get_public_key(None)?;
//! // 4. Ask for a signature; the private key never leaves the signer.
//! let event = signer.sign_event(&serde_json::json!({"kind": 1, "content": "hello"}), None)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The control-channel client used by the GUI and CLI is in [`control`].

pub mod control;
mod error;
pub mod keyfile;
mod signer;

pub use error::ClientError;
pub use signer::{ConnectOptions, PairInfo, SignerClient};
