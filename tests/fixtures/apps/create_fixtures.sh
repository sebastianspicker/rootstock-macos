#!/usr/bin/env bash
# create_fixtures.sh — Build minimal fixture .app bundles for Rootstock tests.
#
# Requirements: macOS with Xcode Command Line Tools (codesign).
# All apps use ad-hoc signing (codesign --sign -) since no developer cert is needed.
#
# Usage:
#   bash tests/fixtures/apps/create_fixtures.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Minimal valid Info.plist template
make_plist() {
    local bundle_id="$1"
    local name="$2"
    cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>${bundle_id}</string>
    <key>CFBundleName</key>
    <string>${name}</string>
    <key>CFBundleExecutable</key>
    <string>${name}</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
</dict>
</plist>
PLIST
}

# Create a minimal Mach-O executable (just an empty file works for ad-hoc signing)
make_binary() {
    local path="$1"
    # Compile a trivial C main so codesign has a real Mach-O to sign
    echo 'int main(){return 0;}' | cc -x c - -o "$path" 2>/dev/null || \
        # Fallback: copy /bin/echo if cc not available (still a valid Mach-O)
        cp /bin/echo "$path"
}

# ── HardenedApp.app ──────────────────────────────────────────────────────────
APP="$SCRIPT_DIR/HardenedApp.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
make_plist "com.rootstock.test.hardened" "HardenedApp" > "$APP/Contents/Info.plist"
make_binary "$APP/Contents/MacOS/HardenedApp"
codesign --sign - --options runtime --force "$APP"
echo "  HardenedApp.app     — hardened runtime (ad-hoc signed)"

# ── UnhardenedApp.app ────────────────────────────────────────────────────────
APP="$SCRIPT_DIR/UnhardenedApp.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
make_plist "com.rootstock.test.unhardened" "UnhardenedApp" > "$APP/Contents/Info.plist"
make_binary "$APP/Contents/MacOS/UnhardenedApp"
codesign --sign - --force "$APP"
echo "  UnhardenedApp.app   — no hardened runtime (ad-hoc signed)"

# ── ElectronApp.app ──────────────────────────────────────────────────────────
APP="$SCRIPT_DIR/ElectronApp.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Frameworks/Electron Framework.framework"
make_plist "com.rootstock.test.electron" "ElectronApp" > "$APP/Contents/Info.plist"
make_binary "$APP/Contents/MacOS/ElectronApp"
# Electron detection uses the presence of "Electron Framework.framework" dir, not signing
codesign --sign - --force "$APP/Contents/MacOS/ElectronApp" 2>/dev/null || true
echo "  ElectronApp.app     — Electron Framework present (ad-hoc signed binary)"

# ── UnsignedApp.app ──────────────────────────────────────────────────────────
APP="$SCRIPT_DIR/UnsignedApp.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
make_plist "com.rootstock.test.unsigned" "UnsignedApp" > "$APP/Contents/Info.plist"
make_binary "$APP/Contents/MacOS/UnsignedApp"
# Deliberately NOT calling codesign
echo "  UnsignedApp.app     — no code signature"

# ── WithEntitlements.app ─────────────────────────────────────────────────────
APP="$SCRIPT_DIR/WithEntitlements.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
make_plist "com.rootstock.test.entitlements" "WithEntitlements" > "$APP/Contents/Info.plist"
make_binary "$APP/Contents/MacOS/WithEntitlements"

# Entitlements plist
cat > /tmp/rootstock-test-entitlements.plist <<'ENTITLEMENTS'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.app-sandbox</key>
    <false/>
</dict>
</plist>
ENTITLEMENTS

codesign --sign - --entitlements /tmp/rootstock-test-entitlements.plist --force "$APP"
echo "  WithEntitlements.app — allow-dyld-environment-variables + disable-library-validation"

echo ""
echo "All fixture apps created in $SCRIPT_DIR"
