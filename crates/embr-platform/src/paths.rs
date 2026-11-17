//! Where Embr keeps its files and sockets, and checks that those places are private.

use std::io;
use std::path::{Path, PathBuf};

/// Longest socket path we accept (`sun_path` is 104 bytes on macOS, 108 on Linux).
pub const MAX_SOCKET_PATH: usize = 100;

/// Current user's numeric id (Unix) — used to name and verify per-user directories.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Placeholder on platforms without numeric uids.
#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    0
}

/// Directory for runtime files (sockets, instance lock). Per user, private, not persisted.
///
/// Linux: `$XDG_RUNTIME_DIR/embr`; fallback and macOS: `$TMPDIR/embr-<uid>` (or `/tmp/embr-<uid>`).
pub fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("EMBR_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if cfg!(target_os = "linux") {
        if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            if x.is_absolute() {
                return x.join("embr");
            }
        }
    }
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(format!("embr-{}", current_uid()))
}

/// Directory for persistent data (the vault, audit log).
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("EMBR_DATA_DIR") {
        return PathBuf::from(dir);
    }
    user_data_base().join("embr")
}

/// The per-user data base directory following each platform's convention
/// (Linux `$XDG_DATA_HOME` or `~/.local/share`; macOS `~/Library/Application Support`;
/// Windows `%LOCALAPPDATA%`). Implemented here instead of pulling a crate for three `if`s.
fn user_data_base() -> PathBuf {
    let home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        if let Some(p) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(p);
        }
    } else if cfg!(target_os = "macos") {
        if let Some(h) = home() {
            return h.join("Library").join("Application Support");
        }
    } else {
        if let Some(x) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
            if x.is_absolute() {
                return x;
            }
        }
        if let Some(h) = home() {
            return h.join(".local").join("share");
        }
    }
    PathBuf::from(".")
}

/// Client-API socket path (`EMBR_SIGNER_SOCKET` overrides).
pub fn signer_socket() -> PathBuf {
    std::env::var_os("EMBR_SIGNER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| runtime_dir().join("signer.sock"))
}

/// Control-channel socket path (`EMBR_CONTROL_SOCKET` overrides).
pub fn control_socket() -> PathBuf {
    std::env::var_os("EMBR_CONTROL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| runtime_dir().join("control.sock"))
}

/// Creates `dir` (and parents) if needed with mode `0700`, then verifies it with
/// [`verify_private_dir`].
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    verify_private_dir(dir)
}

/// Refuses a directory that could let another user squat or read our endpoints: it must be a real
/// directory (not a symlink), owned by the current user, with no group/other permissions.
pub fn verify_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(dir)?;
        let bad = |msg: &str| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{}: {msg}", dir.display()),
            )
        };
        if !meta.is_dir() {
            return Err(bad("not a directory (or a symlink)"));
        }
        if meta.uid() != current_uid() {
            return Err(bad("not owned by the current user"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(bad("accessible by other users; expected mode 0700"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(dir).map(|_| ())
    }
}

/// Rejects socket paths that would be silently truncated by the OS.
pub fn check_socket_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "socket path too long ({} > {MAX_SOCKET_PATH} bytes)",
                path.as_os_str().len()
            ),
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn private_dir_is_created_and_verified() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("a/b");
        ensure_private_dir(&d).unwrap();
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        verify_private_dir(&d).unwrap();
    }

    #[test]
    fn world_accessible_or_symlinked_dirs_are_refused() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("open");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_private_dir(&d).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(verify_private_dir(&d).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(
            verify_private_dir(&link).is_err(),
            "a symlink could point anywhere"
        );
        assert!(verify_private_dir(&t.path().join("missing")).is_err());
    }

    #[test]
    fn long_socket_paths_are_refused() {
        assert!(check_socket_path(Path::new("/run/user/1000/embr/signer.sock")).is_ok());
        assert!(check_socket_path(Path::new(&format!("/{}", "a".repeat(120)))).is_err());
    }
}
