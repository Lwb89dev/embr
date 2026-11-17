//! Storing the **client key** (your app's own identity towards the signer).
//!
//! This key is *not* a user key. Anyone who can read this file can impersonate your app to the
//! signer — within the grants the user gave it — so it is created `0600` and refused if it is
//! readable by others. Same-user malware can still read it; see `docs/THREAT_MODEL.md`.

use std::io::{self, Write};
use std::path::Path;

use embr_crypto::Identity;

/// Loads the client key at `path`, creating a fresh one (atomically, mode `0600`) if absent.
pub fn load_or_create(path: impl AsRef<Path>) -> io::Result<Identity> {
    let path = path.as_ref();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => {
            check_mode(path)?;
            Identity::from_secret_str(text.trim())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "corrupt client key file"))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let id = Identity::generate();
            let secret = id
                .reveal_nsec()
                .map_err(|_| io::Error::other("cannot encode key"))?;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(path) {
                Ok(mut f) => {
                    f.write_all(secret.as_bytes())?;
                    f.write_all(b"\n")?;
                    f.sync_all()?;
                    Ok(id)
                }
                // Lost a creation race with another process of the same app: use theirs.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => load_or_create(path),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn check_mode(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is accessible by other users (mode {mode:03o}); chmod 600",
                    path.display()
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn creates_once_and_reloads_the_same_key() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("cfg/app.key");
        let a = load_or_create(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let b = load_or_create(&p).unwrap();
        assert_eq!(a.pubkey_hex(), b.pubkey_hex());
    }

    #[test]
    fn group_readable_or_corrupt_files_are_refused() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("app.key");
        load_or_create(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_or_create(&p).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&p, "garbage").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_or_create(&p).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
