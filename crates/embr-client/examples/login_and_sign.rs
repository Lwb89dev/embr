//! A complete native-app integration: log in with Embr, sign a note, encrypt a message — without
//! the app ever seeing a private key.
//!
//! ```text
//! cargo run -p embr-client --example login_and_sign            # uses the default per-user socket
//! EMBR_SIGNER_SOCKET=/path/to/signer.sock cargo run -p embr-client --example login_and_sign
//! ```
//! The first run makes Embr ask the user to approve "Embr example app" (answer in the Embr
//! desktop app or with `embrctl watch`); later runs reuse the pairing.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use embr_client::{ClientError, ConnectOptions, SignerClient, keyfile};
use embr_ipc::ErrorCode;
use serde_json::json;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1. The app's own client key. It identifies *this app* to the signer; it is not a user key.
    let key_path = std::env::var_os("EMBR_EXAMPLE_KEY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("embr-example-{}.key", embr_platform_uid()))
        });
    let identity = keyfile::load_or_create(&key_path)?;

    // 2. Connect + authenticate (proof of possession of the client key).
    let mut signer = match SignerClient::connect(&identity, ConnectOptions::new("Embr example app"))
    {
        Ok(s) => s,
        Err(ClientError::Connect(e)) => {
            return Err(format!("the signer is not running ({e}); start `embrd` first").into());
        }
        Err(e) => return Err(e.into()),
    };
    if signer.locked {
        println!("The vault is locked — unlock it in Embr, then run this again.");
        return Ok(());
    }

    // 3. Log in. A new app triggers a pairing prompt; the user chooses the account.
    println!("Asking Embr to log in (approve in the Embr app or `embrctl watch`)…");
    let pubkey = signer.get_public_key(None)?;
    println!("Logged in as {pubkey}");

    // 4. Ask for a signature. Embr shows the user exactly what will be signed.
    let note = json!({"kind": 1, "content": "Hello from a native app — signed by Embr", "tags": [["t", "embr"]]});
    match signer.sign_event(&note, None) {
        Ok(event) => {
            event.verify()?;
            println!(
                "Signed event {}:\n{}",
                event.id,
                serde_json::to_string_pretty(&event)?
            );
        }
        Err(e) if e.code() == Some(ErrorCode::Denied) => println!("The user declined to sign."),
        Err(e) => return Err(e.into()),
    }

    // 5. NIP-44 encryption to ourselves (a separate permission from signing).
    match signer.nip44_encrypt(&pubkey, "a private note", None) {
        Ok(ct) => println!(
            "NIP-44 ciphertext: {}…",
            ct.chars().take(32).collect::<String>()
        ),
        Err(e) if e.code() == Some(ErrorCode::Denied) => println!("The user declined to encrypt."),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn embr_platform_uid() -> u32 {
    embr_platform::paths::current_uid()
}
