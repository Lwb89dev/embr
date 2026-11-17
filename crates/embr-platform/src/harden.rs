//! Process hardening for the daemon: no core dumps, not debuggable by same-user processes (where
//! the OS allows), no privilege gain. Lessons from Omostrich's security assessment: a crash while
//! unlocked on a system with `systemd-coredump` would otherwise write key material to disk.
//!
//! Each measure is best-effort and **reported**, never silently assumed.

/// What was applied.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HardeningReport {
    /// Measures that succeeded.
    pub applied: Vec<&'static str>,
    /// Measures that failed or are unavailable, with the reason.
    pub failed: Vec<(&'static str, String)>,
}

/// Applies the process hardening available on this OS.
///
/// **Call this at the very start of `main`, before any thread is created.** `NO_NEW_PRIVS` is a
/// per-thread attribute that threads inherit from their creator at creation time; applying it after
/// a runtime has spawned its workers would leave those workers without it.
pub fn harden_process() -> HardeningReport {
    let mut r = HardeningReport::default();
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        match setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        ) {
            Ok(()) => r.applied.push("RLIMIT_CORE=0 (no core dumps)"),
            Err(e) => r.failed.push(("RLIMIT_CORE=0", e.to_string())),
        }
    }
    #[cfg(target_os = "linux")]
    {
        match rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        {
            Ok(()) => r
                .applied
                .push("PR_SET_DUMPABLE=0 (no ptrace/mem read by non-root peers)"),
            Err(e) => r.failed.push(("PR_SET_DUMPABLE=0", e.to_string())),
        }
        match rustix::thread::set_no_new_privs(true) {
            Ok(()) => r.applied.push("PR_SET_NO_NEW_PRIVS"),
            Err(e) => r.failed.push(("PR_SET_NO_NEW_PRIVS", e.to_string())),
        }
    }
    r
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Runs in a child process so that hardening this test binary cannot affect other tests.
    #[test]
    fn measures_are_applied_and_visible_in_proc() {
        if std::env::var_os("EMBR_HARDEN_CHILD").is_some() {
            let r = harden_process();
            assert!(r.failed.is_empty(), "{r:?}");
            let status = std::fs::read_to_string("/proc/thread-self/status").unwrap_or_default();
            assert!(status.contains("NoNewPrivs:\t1"), "{status}");
            assert_eq!(
                rustix::process::dumpable_behavior().ok(),
                Some(rustix::process::DumpableBehavior::NotDumpable)
            );
            let limits = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
            let core = limits
                .lines()
                .find(|l| l.starts_with("Max core file size"))
                .unwrap_or("");
            assert!(
                core.split_whitespace().rev().take(3).any(|w| w == "0"),
                "{core}"
            );
            return;
        }
        let exe = std::env::current_exe().unwrap_or_default();
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "harden::tests::measures_are_applied_and_visible_in_proc",
                "--nocapture",
            ])
            .env("EMBR_HARDEN_CHILD", "1")
            .output()
            .unwrap_or_else(|e| panic!("cannot spawn: {e}"));
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
