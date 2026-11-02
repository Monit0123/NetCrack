#!/bin/bash
# Build NetCrack.app and package it as a distributable .dmg.
#
#   ./Scripts/make-dmg.sh              Release build -> ./dist/NetCrack.dmg
#   ./Scripts/make-dmg.sh --debug      Debug build   -> ./dist/NetCrack-debug.dmg
#
# The app is ad-hoc signed ("-"), so no paid Apple Developer account is needed.
# It is not notarised: on another Mac, right-click > Open the first time, or run
#   xattr -dr com.apple.quarantine /Applications/NetCrack.app

set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG="Release"
NAME="NetCrack"
if [ "${1:-}" = "--debug" ]; then
  CONFIG="Debug"
  NAME="NetCrack-debug"
fi

command -v xcodebuild >/dev/null 2>&1 || {
  echo "xcodebuild not found. Install Xcode (or: xcode-select --install)." >&2
  exit 1
}
command -v hdiutil >/dev/null 2>&1 || {
  echo "hdiutil not found — this script has to run on macOS." >&2
  exit 1
}

echo "==> Building $CONFIG"
xcodebuild \
  -project NetCrack.xcodeproj \
  -scheme NetCrack \
  -configuration "$CONFIG" \
  -destination 'generic/platform=macOS' \
  -derivedDataPath build \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGN_STYLE=Manual \
  DEVELOPMENT_TEAM="" \
  build

APP="build/Build/Products/$CONFIG/NetCrack.app"
[ -d "$APP" ] || { echo "No app at $APP" >&2; exit 1; }

echo "==> Ad-hoc signing"
codesign --force --deep --sign - --timestamp=none "$APP"
codesign --verify --verbose=2 "$APP"

echo "==> Staging"
rm -rf dist/stage
mkdir -p dist/stage
cp -R "$APP" dist/stage/
ln -sfn /Applications dist/stage/Applications

echo "==> Creating DMG"
hdiutil create \
  -volname "$NAME" \
  -srcfolder dist/stage \
  -fs HFS+ \
  -fsargs "-c c=64,a=16,e=16" \
  -format UDZO \
  -imagekey zlib-level=9 \
  -ov "dist/$NAME.dmg"

shasum -a 256 "dist/$NAME.dmg" | tee "dist/$NAME.dmg.sha256"
ls -lh "dist/$NAME.dmg"
echo
echo "Done: $(pwd)/dist/$NAME.dmg"
