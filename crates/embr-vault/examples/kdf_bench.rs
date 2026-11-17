//! Measures the wall-clock cost of unlocking a vault with the given Argon2id parameters.
//!
//! ```text
//! cargo run --release -p embr-vault --example kdf_bench            # default parameters
//! cargo run --release -p embr-vault --example kdf_bench -- 65536 3 4   # m_kib t p
//! ```
//!
//! Results depend entirely on the machine; see `docs/BENCHMARKS.md` for the procedure and the
//! values we measured (with the hardware they were measured on).
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::time::Instant;

use embr_vault::{KdfParams, Vault};

fn main() {
    let args: Vec<u32> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let params = match args.as_slice() {
        [m, t, p] => KdfParams {
            m_kib: *m,
            t_cost: *t,
            p_cost: *p,
        },
        _ => KdfParams::DEFAULT,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.embr");
    let pw = "benchmark passphrase, not a secret";

    let t0 = Instant::now();
    let mut v = Vault::create_with(&path, pw, params).unwrap();
    println!("create (1 KDF + 1 write): {:?}", t0.elapsed());
    v.lock();

    let mut samples = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        v.unlock(pw).unwrap();
        samples.push(t.elapsed());
        v.lock();
    }
    samples.sort();
    println!(
        "params m={} KiB t={} p={}: unlock min={:?} median={:?} max={:?}",
        params.m_kib, params.t_cost, params.p_cost, samples[0], samples[2], samples[4]
    );
}
