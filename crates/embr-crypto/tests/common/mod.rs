//! Helpers shared by the integration tests.
#![allow(dead_code, unreachable_pub)]

use std::path::PathBuf;

/// Path of a file in the repository-level `tests/vectors` directory.
pub fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(name)
}

/// Reads and parses a JSON vector file.
pub fn load_json(name: &str) -> serde_json::Value {
    let path = vector_path(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad JSON in {}: {e}", path.display()))
}

/// Decodes a 32-byte hex string.
pub fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap_or_else(|e| panic!("bad hex32 {s:?}: {e}"));
    out
}
