//! Crash-safe, permission-restricted file writes.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use tempfile::Builder;

use crate::VaultError;
use crate::format::MAX_FILE_BYTES;

/// Creates the vault directory (and parents) with owner-only permissions on Unix.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        // On Windows the directory inherits the ACL of its parent (the user's profile), which is
        // user-private by default. See docs/THREAT_MODEL.md.
        fs::create_dir_all(dir)
    }
}

/// Atomically writes `bytes` to `path`:
/// temp file in the same directory (mode 0600 on Unix) → `fsync` → rename → `fsync` directory.
///
/// A crash at any point leaves either the previous file or the new one, never a mixture.
/// With `must_not_exist`, the final step fails with [`VaultError::AlreadyExists`] instead of
/// replacing an existing file (race-free: it does not rely on a prior existence check).
pub(crate) fn write_atomic(
    path: &Path,
    bytes: &[u8],
    must_not_exist: bool,
) -> Result<(), VaultError> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure_private_dir(dir)?;

    let mut tmp = Builder::new()
        .prefix(".embr-vault-")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;

    if must_not_exist {
        tmp.persist_noclobber(path).map_err(|e| {
            if e.error.kind() == io::ErrorKind::AlreadyExists {
                VaultError::AlreadyExists
            } else {
                VaultError::Io(e.error)
            }
        })?;
    } else {
        tmp.persist(path).map_err(|e| VaultError::Io(e.error))?;
    }

    #[cfg(unix)]
    {
        // Make the rename itself durable.
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Reads a vault file, refusing anything larger than [`MAX_FILE_BYTES`].
pub(crate) fn read_limited(path: &Path) -> Result<Vec<u8>, VaultError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(VaultError::NotFound),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(VaultError::Malformed("file too large"));
    }
    Ok(buf)
}

/// Human-readable warnings about the file's permissions (Unix only; empty elsewhere).
pub(crate) fn permission_warnings(path: &Path) -> Vec<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut warnings = Vec::new();
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warnings.push(format!(
                    "vault file is accessible by other users (mode {mode:03o}); run chmod 600"
                ));
            }
        }
        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(meta) = fs::metadata(dir) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    warnings.push(format!(
                        "vault directory is accessible by other users (mode {mode:03o}); run chmod 700"
                    ));
                }
            }
        }
        warnings
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Vec::new()
    }
}
