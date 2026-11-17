//! Single-instance lock: at most one daemon per user.

use std::fs::File;
use std::io;
use std::path::Path;

/// Holds the lock for as long as it is alive; released by the OS when the process exits, even on
/// a crash, so a stale lock cannot survive.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Tries to take the lock at `path`. `Ok(None)` means another instance holds it.
    pub fn acquire(path: &Path) -> io::Result<Option<InstanceLock>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)?;
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => Ok(Some(InstanceLock { _file: file })),
                Err(e) if e == rustix::io::Errno::WOULDBLOCK => Ok(None),
                Err(e) => Err(io::Error::from(e)),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // share_mode(0): no other handle can open the file while we hold it.
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .share_mode(0)
                .open(path)
            {
                Ok(file) => Ok(Some(InstanceLock { _file: file })),
                Err(e) if e.raw_os_error() == Some(32) => Ok(None), // ERROR_SHARING_VIOLATION
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_fails_until_the_first_is_dropped() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("embrd.lock");
        let first = InstanceLock::acquire(&p).unwrap().unwrap();
        assert!(InstanceLock::acquire(&p).unwrap().is_none());
        drop(first);
        // `flock` locks belong to the open file *description*. Another test in this process spawns a
        // child (fork+exec); in the instant between fork and exec the child still shares that
        // description, so the lock can look held for a few microseconds. Retry briefly.
        let mut reacquired = false;
        for _ in 0..200 {
            if InstanceLock::acquire(&p).unwrap().is_some() {
                reacquired = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            reacquired,
            "the lock must be released once the holder is dropped"
        );
    }
}
