# Benchmarks

Only values that were actually measured are listed. Everything else is explicitly "not measured".

## Machine used
AMD Ryzen 9 8940HX (32 threads), 30 GiB RAM, Linux 7.2.15 (Omarchy), rustc 1.100.0, release profile
(`opt-level = 3`, fat LTO, `codegen-units = 1`). Single run of the example, 5 unlocks each,
2026-11-17. **These are numbers for this machine only; slower machines will be several times slower.**

## Vault unlock (Argon2id), measured
Procedure: `cargo run --release -p embr-vault --example kdf_bench [-- m_kib t p]`

| Parameters | min | median | max |
|---|---:|---:|---:|
| m=19 456 KiB, t=2, p=1 (OWASP minimum; used by tests) | 10.3 ms | 10.7 ms | 11.8 ms |
| m=131 072 KiB, t=3, p=4 | 139 ms | 142 ms | 151 ms |
| **m=262 144 KiB, t=3, p=4 (Embr default)** | **295 ms** | **301 ms** | **308 ms** |

Lanes (`p`) are evaluated sequentially (we don't enable argon2's `parallel` feature), so cost ≈ m × t.
Peak memory during unlock ≈ m (256 MiB at the default), released afterwards.

## Not yet measured (no binary exists to measure)
Executable size · idle RSS · startup latency · idle CPU · battery impact · daemon crash-recovery time.
Procedure to follow when `embrd` exists:
1. `cargo build --release -p embrd`; record `ls -l` and `size`.
2. Start with vault locked/unlocked; after 60 s read `VmRSS` from `/proc/<pid>/status`; 60 s of `pidstat -u`.
3. Startup: median of 20 runs of `embrd --version` and of "socket accepting connections".
4. Repeat on a low-end ARM64 board and a 2015-era laptop; report hardware with the numbers.

## GUI spike (decides ADR-3) — not yet run
Build an equivalent "approval window" (one window, a list, two buttons, a tray icon) in Slint and in
Tauri 2; on a **clean** Ubuntu 24.04, Fedora and openSUSE container/VM record: package install size
incl. dependencies, idle RSS (all processes, `smem -P`), cold start to first paint, tray behaviour on
Wayland (Hyprland/GNOME/KDE) and X11, and screen-reader output (Orca). Gate for Slint: no blocker in the
screen-reader test and a material idle-RSS/size advantage.
