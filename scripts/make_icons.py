#!/usr/bin/env python3
"""Generates the platform icon sets from assets/icons/icon.png.

Output (all under packaging/icons/, committed so that building a package needs no image tools):
  hicolor/<N>x<N>/apps/embr.png   freedesktop icon theme sizes (Linux)
  embr.ico                        Windows (16..256 px, PNG-compressed entries)
  embr.icns                       macOS (PNG entries 16..1024 px)

Needs ImageMagick (`magick`) to resize. The .icns container is written here, because it is a trivial format
(a header plus tagged PNG blobs) and `iconutil` exists only on macOS.

Usage: scripts/make_icons.py            # regenerate
       scripts/make_icons.py --check    # verify the committed files are well-formed (no ImageMagick needed)
"""
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "icons" / "icon.png"
OUT = ROOT / "packaging" / "icons"
HICOLOR = [16, 24, 32, 48, 64, 128, 256, 512]
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]
# ICNS element types that carry PNG data, by pixel size.
ICNS_TYPES = {16: b"icp4", 32: b"icp5", 64: b"icp6", 128: b"ic07", 256: b"ic08", 512: b"ic09", 1024: b"ic10"}
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def resize(size: int) -> bytes:
    return subprocess.run(
        ["magick", str(SRC), "-filter", "Lanczos", "-resize", f"{size}x{size}", "-strip", "png:-"],
        check=True, capture_output=True,
    ).stdout


def png_size(data: bytes) -> tuple[int, int]:
    assert data[:8] == PNG_MAGIC, "not a PNG"
    return struct.unpack(">II", data[16:24])


def build_ico(pngs: dict[int, bytes]) -> bytes:
    """ICO with PNG-compressed entries (supported since Windows Vista). 256 is stored as 0."""
    sizes = sorted(pngs)
    head = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries, blobs = b"", b""
    for s in sizes:
        d = pngs[s]
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(d), offset)
        blobs += d
        offset += len(d)
    return head + entries + blobs


def build_icns(pngs: dict[int, bytes]) -> bytes:
    body = b""
    for s in sorted(pngs):
        body += ICNS_TYPES[s] + struct.pack(">I", 8 + len(pngs[s])) + pngs[s]
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def generate() -> None:
    cache = {s: resize(s) for s in sorted(set(HICOLOR) | set(ICO_SIZES) | set(ICNS_TYPES))}
    for s in HICOLOR:
        p = OUT / "hicolor" / f"{s}x{s}" / "apps" / "embr.png"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(cache[s])
    (OUT / "embr.ico").write_bytes(build_ico({s: cache[s] for s in ICO_SIZES}))
    (OUT / "embr.icns").write_bytes(build_icns({s: cache[s] for s in ICNS_TYPES}))
    print(f"wrote {len(HICOLOR)} PNGs, embr.ico, embr.icns under {OUT.relative_to(ROOT)}")


def check() -> None:
    for s in HICOLOR:
        d = (OUT / "hicolor" / f"{s}x{s}" / "apps" / "embr.png").read_bytes()
        assert png_size(d) == (s, s), f"hicolor {s}: wrong dimensions {png_size(d)}"
    ico = (OUT / "embr.ico").read_bytes()
    reserved, kind, count = struct.unpack("<HHH", ico[:6])
    assert (reserved, kind, count) == (0, 1, len(ICO_SIZES)), "bad ICO header"
    for i in range(count):
        w, h, _, _, planes, bpp, size, off = struct.unpack("<BBBBHHII", ico[6 + 16 * i : 22 + 16 * i])
        data = ico[off : off + size]
        real = png_size(data)
        assert real == (w or 256, h or 256), f"ICO entry {i}: header says {w}x{h}, PNG is {real}"
    icns = (OUT / "embr.icns").read_bytes()
    assert icns[:4] == b"icns" and struct.unpack(">I", icns[4:8])[0] == len(icns), "bad ICNS header/length"
    pos, seen = 8, []
    while pos < len(icns):
        tag, length = icns[pos : pos + 4], struct.unpack(">I", icns[pos + 4 : pos + 8])[0]
        size = png_size(icns[pos + 8 : pos + length])[0]
        assert ICNS_TYPES[size] == tag, f"ICNS element {tag!r} holds a {size}px image"
        seen.append(size)
        pos += length
    assert pos == len(icns) and seen == sorted(ICNS_TYPES), f"ICNS elements: {seen}"
    print("icon sets are well-formed:", len(HICOLOR), "PNGs,", count, "ICO entries,", len(seen), "ICNS elements")


if __name__ == "__main__":
    check() if "--check" in sys.argv else generate()
