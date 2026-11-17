//! Connecting to the daemon's endpoint: a Unix socket, or on Windows a named pipe.

use std::path::Path;

use crate::ClientError;

/// The connected byte stream.
#[cfg(unix)]
pub(crate) type Stream = std::os::unix::net::UnixStream;
/// The connected byte stream (a named pipe opened as a file).
#[cfg(not(unix))]
pub(crate) type Stream = std::fs::File;

/// Connects to `path`.
///
/// Unix: refuses a socket whose directory could have been prepared by another user, then connects.
/// Windows: opens the pipe `\\.\pipe\…` (retrying briefly while all instances are busy). The pipe's
/// DACL (user-only, set by the daemon) is what stops other users; the client cannot verify the server's
/// identity beyond that — see `docs/THREAT_MODEL.md`.
pub(crate) fn connect(path: &Path) -> Result<Stream, ClientError> {
    #[cfg(unix)]
    {
        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            embr_platform::paths::verify_private_dir(dir).map_err(ClientError::Connect)?;
        }
        Stream::connect(path).map_err(ClientError::Connect)
    }
    #[cfg(not(unix))]
    {
        const ERROR_PIPE_BUSY: i32 = 231;
        let mut last = None;
        for _ in 0..40 {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(f) => return Ok(f),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(ClientError::Connect(e)),
            }
        }
        Err(ClientError::Connect(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "all pipe instances are busy")
        })))
    }
}
