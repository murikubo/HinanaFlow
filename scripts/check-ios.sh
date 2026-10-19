#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
MODE=${1:-simulator}
case "$MODE" in
  simulator) SDK=iphonesimulator; DESTINATION='generic/platform=iOS Simulator' ;;
  device-unsigned) SDK=iphoneos; DESTINATION='generic/platform=iOS' ;;
  *) printf '%s\n' 'Usage: sh scripts/check-ios.sh [simulator|device-unsigned]'; exit 2 ;;
esac
if ! xcodebuild -version >/dev/null 2>&1 || ! xcrun --sdk "$SDK" --show-sdk-path >/dev/null 2>&1; then
    printf '%s\n' 'BLOCKED: full Xcode and the selected iOS SDK are required. No iOS build or device installation was performed.'
    exit 2
fi
# No account login, signing-key lookup, provisioning download or device installation.
xcodebuild -project apps/ios/HinanaFlow.xcodeproj -scheme HinanaFlow -configuration Debug \
    -sdk "$SDK" -destination "$DESTINATION" -derivedDataPath .build/ios-"$MODE" \
    CODE_SIGNING_ALLOWED=NO build
printf '%s\n' 'Unsigned build only. This does not prove iPhone installation or real TLS interoperability.'
