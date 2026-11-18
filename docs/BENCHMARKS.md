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

## GUI and binaries (measured 2026-11-18)
One machine (Arch/Omarchy, Hyprland/Wayland, release profile with fat LTO and stripped symbols). The GUI was
started with `embr --demo approvals` (canned data, no daemon); memory read from `/proc/PID/status` three seconds
after start; "window mapped" is polled from the compositor (`hyprctl clients`, ~20 ms granularity), so it
includes that polling.

| Measurement | Result |
|---|---|
| Size: `embr` / `embrd` / `embrctl` | 10.9 MiB / 4.9 MiB / 1.1 MiB |
| `embr` window mapped after process start | 166, 173, 166 ms |
| `embr` resident memory (VmRSS) | 125.7, 125.4, 125.4 MiB; peak equal; 14 threads |
| `embrd` resident memory, idle, no vault | 4.5 MiB |

Reading these: the GUI's RSS includes the OpenGL driver's mapped pages (partly shared with other programs) and
egui's glyph atlas; I did not separate shared from private memory (`smem` was not used). The daemon number was
taken with no vault unlocked, so it does not include a loaded vault or the 256 MiB transient of an Argon2id
derivation (see above). Release `embr --demo` was **not** run on X11, in a container, or on another OS.

## Still not measured
GUI size and memory on macOS/Windows; GUI behaviour on X11, GNOME and KDE; package install size including
distribution dependencies (no packages exist for the GUI); battery impact; low-end ARM64 hardware; daemon
crash-recovery time.
