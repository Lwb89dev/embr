//! Append-only, metadata-only audit log (`audit.jsonl`), rotated at 5 MiB.
//!
//! It records *who asked for what and what happened* — never keys, plaintexts, ciphertexts,
//! signatures or event content. It is a plain file (mode `0600`): it is a record for the user, not
//! a tamper-proof ledger; same-user malware can edit it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use embr_policy::AuditRecord;

const MAX_BYTES: u64 = 5 * 1024 * 1024;

/// The log writer.
pub struct Audit {
    path: PathBuf,
    file: Option<File>,
    written: u64,
}

impl Audit {
    /// Opens (or creates) the log; failures disable logging rather than the daemon.
    pub fn open(path: PathBuf) -> Self {
        let mut a = Audit {
            path,
            file: None,
            written: 0,
        };
        a.reopen();
        a
    }

    fn reopen(&mut self) {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        self.file = opts.open(&self.path).ok();
        self.written = self
            .file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map_or(0, |m| m.len());
    }

    /// Appends a record.
    pub fn record(&mut self, rec: &AuditRecord) {
        if self.written >= MAX_BYTES {
            self.file = None;
            let rotated = self.path.with_extension("jsonl.1");
            let _ = std::fs::rename(&self.path, rotated);
            self.reopen();
        }
        let Some(f) = self.file.as_mut() else { return };
        if let Ok(mut line) = serde_json::to_vec(rec) {
            line.push(b'\n');
            if f.write_all(&line).is_ok() {
                self.written += line.len() as u64;
            }
        }
    }

    /// The last `limit` records (reads the current file only).
    pub fn recent(&self, limit: usize) -> Vec<AuditRecord> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let mut recs: Vec<AuditRecord> = text
            .lines()
            .rev()
            .take(limit.min(1000))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        recs.reverse();
        recs
    }
}
