#!/usr/bin/env bash
# Builds Embr.app and a .dmg from already-built (universal or single-arch) binaries.
#   packaging/macos/build_app.sh <version> <bin-dir> <out-dir>
# <bin-dir> must contain embr, embrd and embrctl. Run from the repository root, on macOS (needs
# hdiutil/codesign). By default the signing is AD-HOC (`codesign -s -`): the bundle runs, but Gatekeeper
# has nothing to trust. Set CODESIGN_IDENTITY for Developer-ID signing; notarising the .dmg is done by the
# release workflow when credentials are configured (see docs/RELEASE.md).
set -euo pipefail

VERSION=${1:?usage: build_app.sh <version> <bin-dir> <out-dir>}
BIN=${2:?bin dir}
OUT=${3:?out dir}
APP="$OUT/Embr.app"

rm -rf "$APP" "$OUT/dmg-root"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$OUT"
# The GUI looks for `embrd` next to its own executable ("Start the daemon").
for b in embr embrd embrctl; do install -m 755 "$BIN/$b" "$APP/Contents/MacOS/$b"; done
install -m 644 packaging/icons/embr.icns "$APP/Contents/Resources/embr.icns"
install -m 644 LICENSE "$APP/Contents/Resources/LICENSE"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Embr</string>
  <key>CFBundleDisplayName</key><string>Embr</string>
  <key>CFBundleIdentifier</key><string>io.github.lwb89dev.embr</string>
  <key>CFBundleExecutable</key><string>embr</string>
  <key>CFBundleIconFile</key><string>embr</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>MIT licence. Pre-alpha, not audited.</string>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist"

# CODESIGN_IDENTITY: a "Developer ID Application: ..." identity (hardened runtime + timestamp, needed for
# notarisation) or "-" for ad-hoc.
ID=${CODESIGN_IDENTITY:--}
if [ "$ID" = "-" ]; then
  codesign --force --deep --sign - "$APP"
else
  codesign --force --deep --options runtime --timestamp --sign "$ID" "$APP"
fi
codesign --verify --deep --strict "$APP"

mkdir -p "$OUT/dmg-root"
cp -R "$APP" "$OUT/dmg-root/"
ln -s /Applications "$OUT/dmg-root/Applications"
hdiutil create -volname "Embr" -srcfolder "$OUT/dmg-root" -ov -format UDZO "$OUT/Embr-${VERSION}-macos.dmg"
rm -rf "$OUT/dmg-root"
echo "built $OUT/Embr-${VERSION}-macos.dmg"
