//! Minimal end-to-end use of the vault: create, add an account, sign without exposing the key, lock.
//! `cargo run -p embr-vault --example quickstart`
#![allow(clippy::print_stdout)]

use embr_crypto::{EventTemplate, Limits};
use embr_vault::{KdfParams, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("vault.embr");

    // Use the default cost in real code: `Vault::create(path, passphrase)`. The minimum keeps this demo instant.
    let mut vault = Vault::create_with(&path, "a long passphrase", KdfParams::MINIMUM)?; // unlocked
    let acct = vault.add_generated("main")?; // the key never leaves the vault
    let limits = Limits::default();
    let tpl = EventTemplate::from_json(r#"{"kind":1,"content":"hello nostr"}"#, &limits)?;
    let event = vault.with_identity(acct.id, |id| id.sign_event(&tpl, &limits))??;
    event.verify()?;
    println!("{} signed event {}", acct.npub, event.id);

    vault.lock(); // wipes keys from memory
    assert!(vault.list_accounts().is_err());
    Ok(())
}
