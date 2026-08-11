#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$ROOT_DIR/desktop/SecFlowTauri"
TRIAL_CONFIG="$TAURI_DIR/src-tauri/tauri.trial.conf.json"
TRIAL_IDENTIFIER="ai.secflow.security-agent.trial7days"
TRIAL_PRODUCT_NAME="安全智脑 7 天试用版"
TARGET_TRIPLE="${SECFLOW_TAURI_TARGET:-aarch64-apple-darwin}"

SECFLOW_TAURI_TRIAL_BUILD=1 \
SECFLOW_TAURI_BACKEND_PORT=18783 \
SECFLOW_TAURI_CONFIG="$TRIAL_CONFIG" \
SECFLOW_TAURI_BUILD_ROOT="${SECFLOW_TAURI_TRIAL_BUILD_ROOT:-${TMPDIR:-/tmp}/secflow-tauri-macos-trial-build}" \
bash "$ROOT_DIR/scripts/build_tauri_macos.sh"

APP_PATH="$TAURI_DIR/src-tauri/target/$TARGET_TRIPLE/release/bundle/macos/$TRIAL_PRODUCT_NAME.app"
DMG_DIR="$TAURI_DIR/src-tauri/target/$TARGET_TRIPLE/release/bundle/dmg"
DMG_PATH="$(find "$DMG_DIR" -maxdepth 1 -type f -name '*7*试用版*.dmg' -print -quit)"

[ -d "$APP_PATH" ] || { echo "Missing trial app bundle: $APP_PATH" >&2; exit 1; }
[ -n "$DMG_PATH" ] && [ -f "$DMG_PATH" ] || { echo "Missing trial DMG in: $DMG_DIR" >&2; exit 1; }
plutil -extract CFBundleIdentifier raw "$APP_PATH/Contents/Info.plist" | grep -qx "$TRIAL_IDENTIFIER"
plutil -extract CFBundleDisplayName raw "$APP_PATH/Contents/Info.plist" | grep -qx "$TRIAL_PRODUCT_NAME"
codesign --verify --deep --strict "$APP_PATH"

printf '%s\n%s\n' "$APP_PATH" "$DMG_PATH"
