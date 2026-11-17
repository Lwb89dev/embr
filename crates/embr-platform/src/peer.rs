//! Hints about the process on the other end of a local connection.
//!
//! **Hints only.** A pid can be recycled, an executable path can be replaced by `exec` after the
//! connection was made, and any same-user process can claim any name. These values exist to help
//! the *user* recognise a request; they are never an authentication factor.

/// Best-effort path of the executable of `pid` (Linux: `/proc/<pid>/exe`).
pub fn exe_of_pid(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.display().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}
