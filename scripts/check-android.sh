#!/bin/sh
# Official wrapper and project-local caches only. No SDK installation or global settings changes.
set -eu
cd "$(dirname "$0")/.."
flow_root="$PWD"
if [ -z "${JAVA_HOME:-}" ]; then
    for flow_java in "$flow_root"/.build/android-tools/*/Contents/Home; do
        if [ -x "$flow_java/bin/java" ]; then JAVA_HOME="$flow_java";export JAVA_HOME;break;fi
    done
fi
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' 'Set JAVA_HOME to an approved JDK 17 installation.' >&2;exit 1
fi
if [ -z "${ANDROID_HOME:-}" ]; then
    printf '%s\n' 'Set ANDROID_HOME to an existing Android SDK with platform 36 and build-tools 35.0.0.' >&2;exit 1
fi
GRADLE_USER_HOME="$flow_root/.build/android-gradle-home";export GRADLE_USER_HOME
case "${1:-build}" in
    build) set -- :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug ;;
    device) set -- :app:connectedDebugAndroidTest ;;
    *) printf '%s\n' 'Usage: check-android.sh [build|device]' >&2;exit 1 ;;
esac
exec sh apps/android/gradlew -p apps/android --console=plain "$@"
