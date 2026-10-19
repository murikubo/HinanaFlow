#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Process-local selection; never changes xcode-select.
if [ -z "${DEVELOPER_DIR:-}" ] && [ -d /Applications/Xcode.app/Contents/Developer ]; then
    DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer; export DEVELOPER_DIR
fi
# Team/account/profile must be configured by the owner. No automatic provisioning
# or account changes here. The app requires Secure Enclave and a signed entitlement.
xcodebuild -project apps/macos/HinanaFlow.xcodeproj -scheme HinanaFlow -configuration Debug \
    -sdk macosx -destination 'platform=macOS' -derivedDataPath .build/macos-signed build
mkdir -p dist
/usr/bin/ditto .build/macos-signed/Build/Products/Debug/HinanaFlow.app dist/HinanaFlow.app
/usr/bin/codesign --verify --strict dist/HinanaFlow.app
printf '%s\n' 'Built development-signed local Secure Enclave diagnostic app. Not a notarized distribution build.'
