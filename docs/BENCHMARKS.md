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
Peak memory during unlock ≈ m (256 MiB at the default; measured 260 MiB RSS), released afterwards.

## Daemon and CLI (release build), measured
Procedure: `cargo build --release -p embrd -p embrctl && python3 -I scripts/bench_daemon.py`
(the script prints machine, kernel and raw numbers; same machine as above, 2026-11-17, build profile
`opt-level = 3`, fat LTO, `panic = "abort"`, stripped).

| Quantity | Result |
|---|---|
| Executable size | `embrd` **3.09 MiB** (3 243 864 B), `embrctl` **1.02 MiB** |
| Startup: process start → signer socket accepts connections (20 runs) | min 0.7 ms, **median 0.7 ms**, max 1.4 ms |
| Idle RSS, no vault | **4.3 MiB**, 3 threads |
| Idle RSS, vault unlocked or locked, 1 account | **4.7 MiB**, 4 threads |
| Idle CPU over 30 s (locked) | **0 ms** (0.000 %) — event-driven, no polling |
| Peak RSS during an unlock at the default Argon2id cost (kernel `VmHWM`) | **260 MiB** (≈ the 256 MiB working set), transient: RSS returns to ≈ 4.7 MiB afterwards |
| Runtime dependencies | `libc`, `libm`, `libgcc_s` only (no OpenSSL, no GTK, no WebView) |

Caveats: one machine; a laptop on battery, a Raspberry Pi or a 2 GB machine will differ (the 256 MiB
unlock peak matters most on small machines — `KdfParams` can be lowered, never below the OWASP minimum).
"Startup" measures socket readiness, not the first unlock. The GUI will add its own footprint (see below).

A benchmark-found bug: the first run of this script showed a ~132 MiB peak, i.e. the code still had the
old 128 MiB default while the documents said 256 MiB. Fixed, and a test now pins the documented value
(`the_default_kdf_cost_is_the_documented_one`).

## Still not measured
GUI size / RSS / startup (no GUI yet); battery impact; low-end ARM64 hardware; daemon crash-recovery time.

## GUI spike (decides ADR-3) — not yet run
Build an equivalent "approval window" (one window, a list, two buttons, a tray icon) in Slint and in
Tauri 2; on a **clean** Ubuntu 24.04, Fedora and openSUSE container/VM record: package install size
incl. dependencies, idle RSS (all processes, `smem -P`), cold start to first paint, tray behaviour on
Wayland (Hyprland/GNOME/KDE) and X11, and screen-reader output (Orca). Gate for Slint: no blocker in the
screen-reader test and a material idle-RSS/size advantage.
