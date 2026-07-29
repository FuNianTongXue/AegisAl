#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${SECFLOW_MACOS_TRIAL_OUTPUT_DIR:-$ROOT_DIR/dist-macos-trial}"
MACOS_ARCH="${SECFLOW_MACOS_ARCH:-arm64}"
if [ "$MACOS_ARCH" = "arm64" ]; then
    APP_DIR="$OUTPUT_DIR/SecFlow-Trial-7Days.app"
else
    APP_DIR="$OUTPUT_DIR/SecFlow-Trial-7Days-$MACOS_ARCH.app"
fi
ZIP_PATH="$OUTPUT_DIR/SecFlow-Trial-7Days-macOS-$MACOS_ARCH.zip"
BASE_PLIST="$ROOT_DIR/macos/SecFlowMac/Resources/Info.plist"
TRIAL_PLIST="$(mktemp "${TMPDIR:-/tmp}/secflow-trial-info.XXXXXX.plist")"

cleanup() {
    rm -f "$TRIAL_PLIST"
}
trap cleanup EXIT

mkdir -p "$OUTPUT_DIR"
cp "$BASE_PLIST" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName 安全智脑 7 天试用版" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleName 安全智脑 7 天试用版" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ai.secflow.knowledge-assistant.trial7days" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Add :SecFlowTrialEnabled bool true" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Add :SecFlowTrialDurationHours integer 168" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Add :SecFlowTrialReleaseChannel string 7天试用版" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Add :SecFlowTrialDataDirectory string SecFlow-Trial-7Days" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Add :SecFlowTrialKeychainService string com.secflow.ai.mac.trial7days" "$TRIAL_PLIST"
/usr/libexec/PlistBuddy -c "Add :SecFlowTrialBackendPort integer 18783" "$TRIAL_PLIST"

SECFLOW_MACOS_APP_DIR="$APP_DIR" \
SECFLOW_MACOS_ARCHIVE_PATH="$ZIP_PATH" \
SECFLOW_MACOS_INFO_PLIST="$TRIAL_PLIST" \
SECFLOW_MACOS_ARCH="$MACOS_ARCH" \
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}" \
bash "$ROOT_DIR/scripts/build_macos_app.sh"

plutil -extract SecFlowTrialEnabled raw "$APP_DIR/Contents/Info.plist" | grep -qx "true"
plutil -extract SecFlowTrialDurationHours raw "$APP_DIR/Contents/Info.plist" | grep -qx "168"
plutil -extract CFBundleIdentifier raw "$APP_DIR/Contents/Info.plist" | grep -qx "ai.secflow.knowledge-assistant.trial7days"
codesign --verify --deep --strict "$APP_DIR"
MAIN_ARCH="$(lipo -archs "$APP_DIR/Contents/MacOS/SecFlowMac")"
BACKEND_ARCH="$(lipo -archs "$APP_DIR/Contents/Resources/backend/secflow-backend")"
SEMGREP_ARCH="$(lipo -archs "$APP_DIR/Contents/Resources/semgrep/secflow-semgrep")"
[ "$MAIN_ARCH" = "$MACOS_ARCH" ] || { echo "Unexpected app architecture: $MAIN_ARCH" >&2; exit 1; }
[ "$BACKEND_ARCH" = "$MACOS_ARCH" ] || { echo "Unexpected backend architecture: $BACKEND_ARCH" >&2; exit 1; }
[ "$SEMGREP_ARCH" = "$MACOS_ARCH" ] || { echo "Unexpected Semgrep architecture: $SEMGREP_ARCH" >&2; exit 1; }

echo "$APP_DIR"
echo "$ZIP_PATH"
shasum -a 256 "$ZIP_PATH"
