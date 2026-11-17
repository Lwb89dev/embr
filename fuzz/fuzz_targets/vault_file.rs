//! Arbitrary bytes as a vault file: opening must fail cleanly (never panic, never allocate
//! unboundedly). Unlocking is not fuzzed: hostile-but-valid KDF parameters are *allowed* to be slow
//! (bounded, ≤1 GiB / t≤16) — they come from a file only the user can write.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!("embr-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("v.embr");
    if std::fs::write(&path, data).is_ok() {
        let _ = embr_vault::Vault::open(&path);
    }
});
