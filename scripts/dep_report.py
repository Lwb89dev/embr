#!/usr/bin/env python3
"""Regenerates the tables in docs/DEPENDENCIES.md from `cargo metadata` / `cargo tree`.

    scripts/dep_report.py            # rewrite the generated block of docs/DEPENDENCIES.md
    scripts/dep_report.py --check    # exit 1 if the committed block is out of date

Only the text between the BEGIN/END GENERATED markers is touched. The purpose of each direct dependency
is written here (PURPOSE); a dependency without an entry is listed as "UNDOCUMENTED" so it cannot slip in
unexplained.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "DEPENDENCIES.md"
BEGIN, END = "<!-- BEGIN GENERATED -->", "<!-- END GENERATED -->"

PURPOSE = {
    "argon2": "Argon2id password hashing for the vault key (RustCrypto)",
    "base64": "encoding of ciphertext/blobs",
    "chacha20poly1305": "XChaCha20-Poly1305 vault encryption (RustCrypto)",
    "clap": "command-line parsing for `embrctl`",
    "eframe": "the desktop GUI toolkit (egui): window, rendering, accessibility",
    "futures-util": "async helpers for the relay client",
    "getrandom": "operating-system randomness (nonces, salts)",
    "hex": "hex encoding of keys and ids",
    "ksni": "system tray icon (StatusNotifierItem over D-Bus), Linux only, `embr --tray`",
    "nostr": "Nostr events, keys, NIP-01/04/06/19/44/49 (rust-nostr; all signing and NIP crypto)",
    "notify-rust": "desktop notifications (metadata only)",
    "qrcode": "QR code of a `bunker://` link",
    "rpassword": "reading a password without echo in `embrctl`",
    "rustix": "safe wrappers over Unix system calls (hardening, locks, sockets)",
    "rustls": "TLS for `wss://` relays (ring provider; see ADR-9)",
    "serde": "(de)serialisation of every wire and storage type",
    "serde_json": "JSON for the protocols and the vault",
    "sha2": "SHA-256 digests (request digests, hashed secrets)",
    "tempfile": "temporary files and atomic writes; temporary directories in tests",
    "thiserror": "error types",
    "tokio": "async runtime of the daemon, relay client and tests",
    "tokio-rustls": "TLS over tokio streams",
    "tokio-tungstenite": "WebSocket client/test relay",
    "tokio-util": "cancellation tokens",
    "unicode-normalization": "NFKC normalisation of passwords (NIP-49)",
    "url": "parsing of `bunker://`, `nostrconnect://` and relay URLs",
    "webpki-roots": "the Mozilla CA root list as data, for `wss://`",
    "windows-sys": "Windows named pipes and security descriptors (Windows only)",
    "zeroize": "wiping secrets from memory",
}


def run(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True).stdout


def generate() -> str:
    meta = json.loads(run("cargo", "metadata", "--format-version", "1", "--locked"))
    members = {p["id"]: p for p in meta["packages"] if p["id"] in meta["workspace_members"]}
    own = {p["name"] for p in members.values()}
    by_name: dict[str, list[dict]] = {}
    for p in meta["packages"]:
        by_name.setdefault(p["name"], []).append(p)

    # Resolved versions come from the resolve graph (what the lock file actually selects for each
    # workspace crate), not from "the newest version in the graph".
    ids = {p["id"]: p for p in meta["packages"]}
    direct: dict[str, set[str]] = {}
    versions: dict[str, set[str]] = {}
    for node in meta["resolve"]["nodes"]:
        if node["id"] not in members:
            continue
        user = members[node["id"]]["name"]
        for dep in node["deps"]:
            pkg = ids[dep["pkg"]]
            if pkg["name"] in own:
                continue
            direct.setdefault(pkg["name"], set()).add(user)
            versions.setdefault(pkg["name"], set()).add(pkg["version"])

    out = [f"Graph: **{len(meta['packages'])} packages** in total (including build/dev/platform-specific ones), "
           f"{len(direct)} direct external dependencies, {len(own)} workspace crates.", "",
           "| Dependency | Version | Licence | Used by | Why |", "|---|---|---|---|---|"]
    for n in sorted(direct):
        v = by_name[n][0]
        why = PURPOSE.get(n, "**UNDOCUMENTED**")
        users = ", ".join(f"`{u}`" for u in sorted(direct[n]))
        ver = " / ".join(sorted(versions[n]))
        out.append(f"| `{n}` | {ver} | {v['license']} | {users} | {why} |")

    out += ["", "Distinct crates each binary pulls in at run time (`cargo tree -p X -e normal`, current host):", "",
            "| Binary | Crates |", "|---|---|"]
    for b in ("embrctl", "embrd", "embr-desktop"):
        tree = run("cargo", "tree", "-p", b, "-e", "normal", "--prefix", "none", "--locked")
        crates = {line.split()[0] + " " + line.split()[1] for line in tree.splitlines() if line.strip()}
        out.append(f"| `{b}` | {len(crates)} |")
    return "\n".join(out)


def main() -> int:
    block = f"{BEGIN}\n{generate()}\n{END}"
    text = DOC.read_text()
    head, rest = text.split(BEGIN)
    _, tail = rest.split(END)
    new = head + block + tail
    if "--check" in sys.argv:
        if new != text:
            print("docs/DEPENDENCIES.md is out of date; run scripts/dep_report.py")
            return 1
        print("docs/DEPENDENCIES.md is up to date")
        return 0
    DOC.write_text(new)
    print("updated", DOC.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
