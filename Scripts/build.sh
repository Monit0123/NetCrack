#!/bin/bash
# Build NetCrack and (optionally) launch it.
#
#   ./Scripts/build.sh            build Debug into ./build
#   ./Scripts/build.sh run        build and open the app
#   ./Scripts/build.sh release    build Release into ./build
#
# No paid Apple Developer account is needed: the project is configured to
# sign to run locally (CODE_SIGN_IDENTITY = "-").

set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG="Debug"
LAUNCH="no"
case "${1:-}" in
  run) LAUNCH="yes" ;;
  release) CONFIG="Release" ;;
  "") ;;
  *) echo "usage: $0 [run|release]" >&2; exit 2 ;;
esac

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild not found. Install Xcode or the Command Line Tools:" >&2
  echo "  xcode-select --install" >&2
  exit 1
fi

echo "==> Building NetCrack ($CONFIG)"
xcodebuild \
  -project NetCrack.xcodeproj \
  -scheme NetCrack \
  -configuration "$CONFIG" \
  -derivedDataPath build \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=YES \
  build

APP="build/Build/Products/$CONFIG/NetCrack.app"
if [ ! -d "$APP" ]; then
  echo "Build finished but $APP is missing." >&2
  exit 1
fi

echo "==> $APP"
if [ "$LAUNCH" = "yes" ]; then
  open "$APP"
fi
