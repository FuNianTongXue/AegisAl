#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$ROOT_DIR/desktop/SecFlowTauri"
VERSION="$(python3 - "$TAURI_DIR/package.json" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["version"])
PY
)"
[ -n "$VERSION" ] || { echo "Unable to read client version from desktop/SecFlowTauri/package.json" >&2; exit 1; }
TRIAL_CONFIG="$TAURI_DIR/src-tauri/tauri.trial.conf.json"
TRIAL_IDENTIFIER="ai.secflow.security-agent.trial7days"
TRIAL_PRODUCT_NAME="神盾 7 天试用版"
TARGET_TRIPLE="${SECFLOW_TAURI_TARGET:-aarch64-apple-darwin}"

SECFLOW_TAURI_TRIAL_BUILD=1 \
SECFLOW_TAURI_BACKEND_PORT=18783 \
SECFLOW_TAURI_CONFIG="$TRIAL_CONFIG" \
SECFLOW_TAURI_BUILD_ROOT="${SECFLOW_TAURI_TRIAL_BUILD_ROOT:-${TMPDIR:-/tmp}/secflow-tauri-macos-trial-build}" \
bash "$ROOT_DIR/scripts/build_tauri_macos.sh"

APP_PATH="$TAURI_DIR/src-tauri/target/$TARGET_TRIPLE/release/bundle/macos/$TRIAL_PRODUCT_NAME.app"
DMG_DIR="$TAURI_DIR/src-tauri/target/$TARGET_TRIPLE/release/bundle/dmg"
case "$TARGET_TRIPLE" in
    aarch64-apple-darwin) DMG_ARCH="aarch64" ;;
    x86_64-apple-darwin) DMG_ARCH="x64" ;;
    *) echo "Unsupported macOS trial target: $TARGET_TRIPLE" >&2; exit 1 ;;
esac
DMG_PATH="$DMG_DIR/${TRIAL_PRODUCT_NAME}_${VERSION}_${DMG_ARCH}.dmg"

[ -d "$APP_PATH" ] || { echo "Missing trial app bundle: $APP_PATH" >&2; exit 1; }
[ -n "$DMG_PATH" ] && [ -f "$DMG_PATH" ] || { echo "Missing trial DMG in: $DMG_DIR" >&2; exit 1; }
plutil -extract CFBundleIdentifier raw "$APP_PATH/Contents/Info.plist" | grep -qx "$TRIAL_IDENTIFIER"
plutil -extract CFBundleDisplayName raw "$APP_PATH/Contents/Info.plist" | grep -qx "$TRIAL_PRODUCT_NAME"
plutil -extract CFBundleShortVersionString raw "$APP_PATH/Contents/Info.plist" | grep -qx "$VERSION"
codesign --verify --deep --strict "$APP_PATH"

printf '%s\n%s\n' "$APP_PATH" "$DMG_PATH"
