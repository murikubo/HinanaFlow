#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
swift run --package-path packages/HinanaFlowApple --scratch-path packages/HinanaFlowApple/.build FlowCoreVectorTests
swift build --package-path apps/macos --scratch-path apps/macos/.build --product HinanaFlow
