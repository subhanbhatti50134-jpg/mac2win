#!/usr/bin/env bash
# Build a universal macOS .app + signed DMG for the Mac2Win sender.
#
# Runs on macOS CI (macos-latest). Prerequisites:
#   - Xcode 16+ (swift 6, xcodebuild)
#   - Apple Developer ID (for codesign/notarize) — set via env vars or leave
#     unsigned for local testing
#
# Usage:
#   ./mac-sender/App/build_dmg.sh
#
# Produces: mac-sender/App/dist/Mac2Win Transfer-0.1.0.dmg
#
# SPEC §11: universal .app (arm64 + x86_64), Info.plist with
# NSLocalNetworkUsageDescription + NSBonjourServices, hardened runtime,
# minimal entitlements, app icon, DMG with Applications shortcut.
# Codesign/notarytool/stapler steps are scripted with env-var placeholders.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
APP_NAME="Mac2Win Sender"
APP_BUNDLE="Mac2WinSender.app"
APP_EXE="Mac2WinSender"
VERSION="0.1.0"
BUILD_DIR="$ROOT/build/Release"
DIST_DIR="$ROOT/dist"
DMG_NAME="Mac2Win Transfer-$VERSION.dmg"
CODESIGN_IDENTITY="${MAC2WIN_CODESIGN_IDENTITY:-}"   # e.g. "Developer ID Application: Acme (TEAMID)"
NOTARY_APPLE_ID="${MAC2WIN_NOTARY_APPLE_ID:-}"
NOTARY_PASSWORD="${MAC2WIN_NOTARY_PASSWORD:-}"       # app-specific password
TEAM_ID="${MAC2WIN_TEAM_ID:-}"

echo "==> Cleaning previous build ..."
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "==> Building universal .app (arm64 + x86_64) ..."
# Requires an Xcode project at mac-sender/App/Mac2WinSender.xcodeproj with a
# "Mac2WinSender" target (SwiftUI app). The app UI itself is written on macOS
# (ADR-010; not buildable on this Windows workstation).
if [[ -f "$ROOT/Mac2WinSender.xcodeproj/project.pbxproj" ]]; then
    xcodebuild -project "$ROOT/Mac2WinSender.xcodeproj" \
        -scheme Mac2WinSender \
        -configuration Release \
        -arch arm64 -arch x86_64 \
        -derivedDataPath "$BUILD_DIR/DerivedData" \
        CODE_SIGN_IDENTITY="" \
        CODE_SIGNING_REQUIRED=NO \
        ENABLE_HARDENED_RUNTIME=NO \
        COPY_PHASE_STRIP=NO \
        ONLY_ACTIVE_ARCH=NO
    APP_PATH="$BUILD_DIR/DerivedData/Build/Products/Release/$APP_BUNDLE"
else
    echo "ERROR: $ROOT/Mac2WinSender.xcodeproj not found."
    echo "   Create the SwiftUI app project in Xcode first (mac-sender/App is empty)."
    exit 1
fi

if [[ ! -d "$APP_PATH" ]]; then
    echo "ERROR: .app not produced at $APP_PATH"
    exit 1
fi

echo "==> Copying Info.plist + entitlements into bundle ..."
cp "$ROOT/Info.plist" "$APP_PATH/Contents/Info.plist"
cp "$ROOT/Entitlements.plist" "$APP_PATH/Contents/Entitlements.plist"

# App icon (optional): place mac-sender/App/Assets.xcassets/AppIcon.appiconset in the
# Xcode project; the build copies it automatically. Placeholder note below.

echo "==> Codesigning (hardened runtime) ..."
if [[ -n "$CODESIGN_IDENTITY" && -n "$TEAM_ID" ]]; then
    codesign --deep --force --sign "$CODESIGN_IDENTITY" \
        --entitlements "$ROOT/Entitlements.plist" \
        --options runtime \
        "$APP_PATH"
    echo "   signed as $CODESIGN_IDENTITY"
else
    echo "   no signing identity (MAC2WIN_CODESIGN_IDENTITY unset) — unsigned .app"
fi

echo "==> Creating DMG ..."
DMG_STAGING="$DIST_DIR/dmg-staging"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"
cp -R "$APP_PATH" "$DMG_STAGING/"
ln -s /Applications "$DMG_STAGING/Applications"

hdiutil create "$DIST_DIR/$DMG_NAME" \
    -volname "Mac2Win Transfer" \
    -srcfolder "$DMG_STAGING" \
    -ov -format UDZO

rm -rf "$DMG_STAGING"

echo "==> Notarizing + stapling (if credentials provided) ..."
if [[ -n "$CODESIGN_IDENTITY" && -n "$NOTARY_APPLE_ID" && -n "$NOTARY_PASSWORD" ]]; then
    xcrun notarytool submit "$DIST_DIR/$DMG_NAME" \
        --apple-id "$NOTARY_APPLE_ID" \
        --password "$NOTARY_PASSWORD" \
        --team-id "$TEAM_ID" \
        --wait
    xcrun stapler staple "$DIST_DIR/$DMG_NAME"
    echo "   notarized + stapled"
else
    echo "   no notary credentials — unsigned DMG (local testing only)"
fi

echo "==> Done: $DIST_DIR/$DMG_NAME"
