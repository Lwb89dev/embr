#!/usr/bin/env bash
# Builds Embr.app and a .dmg from source, on a Mac, with one command.
#
#   packaging/macos/build_dmg.sh [version]
#
# Run it from the repository root. It needs macOS 11 or newer, the Xcode command line tools
# (`xcode-select --install`) and Rust (https://rustup.rs; the pinned toolchain installs itself).
#
# Environment (everything is optional):
#   ARCHS               "universal" (default: Apple silicon + Intel, merged with lipo) or "native"
#                       (this Mac's architecture only: faster, and enough to try it out)
#   OUT                 output directory (default: dist/macos)
#   CODESIGN_IDENTITY   your signing identity, e.g. "Developer ID Application: Your Name (TEAMID)".
#                       Without it the app is signed AD-HOC: it runs, but Gatekeeper warns about it.
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD
#                       if all three are set *and* CODESIGN_IDENTITY is a Developer ID, the .dmg is
#                       submitted to Apple's notary service and the ticket is stapled to it.
#                       APPLE_APP_PASSWORD is an app-specific password (appleid.apple.com), not your
#                       Apple ID password.
#
# What is verified: the ad-hoc path runs in CI on a GitHub macOS runner every time the release workflow
# runs (it calls this very script). The Developer-ID signing and the notarisation steps below have never
# been executed by the maintainers, who have no Apple developer account: treat them as untested and
# report what you find.
set -euo pipefail

cd "$(dirname "$0")/../.."

VERSION=${1:-$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')}
ARCHS=${ARCHS:-universal}
OUT=${OUT:-dist/macos}
PROGRAMS="-p embrd -p embrctl -p embr-desktop"
BINS="embr embrd embrctl"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: this script builds a macOS app and must run on macOS (hdiutil and codesign are needed)" >&2
  exit 1
fi
command -v cargo >/dev/null || { echo "error: cargo not found; install Rust from https://rustup.rs" >&2; exit 1; }

rm -rf "$OUT/bin"
mkdir -p "$OUT/bin"

case "$ARCHS" in
  universal)
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    for t in aarch64-apple-darwin x86_64-apple-darwin; do
      cargo build --release --locked --target "$t" $PROGRAMS
    done
    for b in $BINS; do
      lipo -create -output "$OUT/bin/$b" \
        "target/aarch64-apple-darwin/release/$b" "target/x86_64-apple-darwin/release/$b"
    done
    ;;
  native)
    cargo build --release --locked $PROGRAMS
    for b in $BINS; do cp "target/release/$b" "$OUT/bin/$b"; done
    ;;
  *)
    echo "error: ARCHS must be 'universal' or 'native', not '$ARCHS'" >&2
    exit 1
    ;;
esac
lipo -info "$OUT"/bin/*

packaging/macos/build_app.sh "$VERSION" "$OUT/bin" "$OUT"
dmg="$OUT/Embr-${VERSION}-macos.dmg"

if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ] \
   && [ -n "${CODESIGN_IDENTITY:-}" ] && [ "${CODESIGN_IDENTITY}" != "-" ]; then
  # UNTESTED by the maintainers (no Apple developer account).
  xcrun notarytool submit "$dmg" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" --wait
  xcrun stapler staple "$dmg"
  echo "notarised and stapled: $dmg"
else
  echo "not notarised (needs CODESIGN_IDENTITY plus APPLE_ID, APPLE_TEAM_ID and APPLE_APP_PASSWORD)"
fi

echo
echo "done: $dmg"
