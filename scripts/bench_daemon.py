#!/usr/bin/env python3
"""Reproducible measurements of embrd: startup latency, idle RSS (locked / unlocked), idle CPU.

    cargo build --release -p embrd -p embrctl
    python3 -I scripts/bench_daemon.py [--runs 20] [--idle-seconds 30]

Uses short temporary directories (Unix socket paths are limited to ~100 bytes). Reports raw numbers
only; hardware and kernel are printed so results can be compared honestly.
"""
import argparse, os, platform, shutil, socket, statistics, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EMBRD = os.path.join(ROOT, "target", "release", "embrd")
EMBRCTL = os.path.join(ROOT, "target", "release", "embrctl")
PW = "benchmark passphrase, not a secret"


def rss_kib(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return -1


def hwm_kib(pid):
    """Peak resident set size (kernel high-water mark) since the process started."""
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    return -1


def threads(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("Threads:"):
                return int(line.split()[1])
    return -1


def cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().rsplit(")", 1)[1].split()
    return int(parts[11]) + int(parts[12])  # utime + stime


def start(tmp):
    env = dict(os.environ, EMBR_DATA_DIR=os.path.join(tmp, "d"), EMBR_RUNTIME_DIR=os.path.join(tmp, "r"))
    env.pop("EMBR_SIGNER_SOCKET", None)
    env.pop("EMBR_CONTROL_SOCKET", None)
    t0 = time.perf_counter()
    p = subprocess.Popen([EMBRD], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = os.path.join(tmp, "r", "signer.sock")
    while True:
        s = socket.socket(socket.AF_UNIX)
        try:
            s.connect(sock)
            s.close()
            return p, env, time.perf_counter() - t0
        except OSError:
            s.close()
            if time.perf_counter() - t0 > 5:
                p.kill()
                sys.exit("embrd did not become ready within 5 s")
            time.sleep(0.0005)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--idle-seconds", type=int, default=30)
    a = ap.parse_args()
    for b in (EMBRD, EMBRCTL):
        if not os.path.exists(b):
            sys.exit(f"missing {b}: run `cargo build --release -p embrd -p embrctl` first")

    cpu = "?"
    with open("/proc/cpuinfo") as f:
        for line in f:
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    print(f"machine: {cpu}, {os.cpu_count()} threads, {platform.release()}")
    for b in (EMBRD, EMBRCTL):
        print(f"size {os.path.basename(b)}: {os.path.getsize(b)/1048576:.2f} MiB ({os.path.getsize(b)} bytes)")

    # 1. startup latency: process start -> signer socket accepts connections
    times = []
    for _ in range(a.runs):
        tmp = tempfile.mkdtemp(prefix="b")
        os.chmod(tmp, 0o700)
        p, _, dt = start(tmp)
        times.append(dt * 1000)
        p.terminate()
        p.wait()
        shutil.rmtree(tmp, ignore_errors=True)
    times.sort()
    print(f"startup to ready ({a.runs} runs): min {times[0]:.1f} ms, median {statistics.median(times):.1f} ms, max {times[-1]:.1f} ms")

    # 2. idle memory/CPU, locked then unlocked
    tmp = tempfile.mkdtemp(prefix="b")
    os.chmod(tmp, 0o700)
    p, env, _ = start(tmp)
    try:
        time.sleep(0.5)
        print(f"idle, no vault:        RSS {rss_kib(p.pid)/1024:.1f} MiB, {threads(p.pid)} threads")
        subprocess.run([EMBRCTL, "--password-stdin", "init"], input=PW + "\n", text=True, env=env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([EMBRCTL, "--password-stdin", "accounts", "add", "main"], input=PW + "\n", text=True, env=env, check=True, stdout=subprocess.DEVNULL)
        time.sleep(0.5)
        print(f"idle, unlocked (1 acct, default KDF already freed): RSS {rss_kib(p.pid)/1024:.1f} MiB, {threads(p.pid)} threads")
        subprocess.run([EMBRCTL, "--password-stdin", "lock"], input=PW + "\n", text=True, env=env, check=True, stdout=subprocess.DEVNULL)
        time.sleep(0.5)
        r0, c0, t0 = rss_kib(p.pid), cpu_ticks(p.pid), time.time()
        time.sleep(a.idle_seconds)
        c1, t1 = cpu_ticks(p.pid), time.time()
        hz = os.sysconf("SC_CLK_TCK")
        print(f"idle, locked:          RSS {r0/1024:.1f} MiB; CPU over {t1-t0:.0f} s idle: {(c1-c0)/hz*1000:.0f} ms total ({(c1-c0)/hz/(t1-t0)*100:.3f} %)")
        # peak during unlock: kernel high-water mark, exact (the Argon2id working set is transient)
        before = hwm_kib(p.pid)
        subprocess.run([EMBRCTL, "--password-stdin", "unlock"], input=PW + "\n", text=True, env=env, check=True, stdout=subprocess.DEVNULL)
        print(f"peak RSS (VmHWM) after an unlock with the default Argon2id cost: {hwm_kib(p.pid)/1024:.0f} MiB (before this unlock: {before/1024:.0f} MiB)")
    finally:
        p.terminate()
        p.wait()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
