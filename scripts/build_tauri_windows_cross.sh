#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$ROOT_DIR/desktop/SecFlowTauri"
TAURI_SOURCE_DIR="$TAURI_DIR/src-tauri"
RESOURCES_DIR="$TAURI_SOURCE_DIR/resources"
TRANSLATION_MODEL_DIR="$ROOT_DIR/app/resources/translation-models/opus-mt-en-zh-1.9"
BUILD_ROOT="${SECFLOW_WINDOWS_CROSS_BUILD_ROOT:-${TMPDIR:-/tmp}/secflow-windows-cross}"
PYTHON_ARCHIVE="$BUILD_ROOT/python-windows-x86_64.tar.gz"
PYTHON_URL="${SECFLOW_WINDOWS_PYTHON_URL:-https://github.com/astral-sh/python-build-standalone/releases/download/20260807/cpython-3.11.15%2B20260807-x86_64-pc-windows-msvc-install_only_stripped.tar.gz}"
EDITION="${1:-formal}"
VERSION="$(python3 - "$TAURI_DIR/package.json" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["version"])
PY
)"
[ -n "$VERSION" ] || { echo "Unable to read client version from desktop/SecFlowTauri/package.json" >&2; exit 1; }

case "$EDITION" in
    formal) BACKEND_PORT=18781; TRIAL_BUILD=0; EDITION_LABEL="Formal" ;;
    trial) BACKEND_PORT=18783; TRIAL_BUILD=1; EDITION_LABEL="Trial-7Days" ;;
    *) echo "Usage: $0 [formal|trial]" >&2; exit 2 ;;
esac

command -v cargo-xwin >/dev/null || { echo "cargo-xwin is required" >&2; exit 1; }
command -v makensis >/dev/null || { echo "NSIS makensis is required" >&2; exit 1; }
python3 "$ROOT_DIR/scripts/validate_translation_model.py" "$TRANSLATION_MODEL_DIR"
mkdir -p "$BUILD_ROOT"
if [ ! -f "$PYTHON_ARCHIVE" ]; then
    curl --noproxy '*' -L --fail --retry 3 -o "$PYTHON_ARCHIVE" "$PYTHON_URL"
fi

rm -rf "$BUILD_ROOT/python" "$RESOURCES_DIR"
tar -xzf "$PYTHON_ARCHIVE" -C "$BUILD_ROOT"
mkdir -p "$RESOURCES_DIR/backend/Lib/site-packages" "$RESOURCES_DIR/semgrep" \
    "$RESOURCES_DIR/semgrep-rules" "$RESOURCES_DIR/licenses"
cp -R "$BUILD_ROOT/python/." "$RESOURCES_DIR/backend/"
cp -R "$ROOT_DIR/app" "$RESOURCES_DIR/backend/app"

python3 -m pip install \
    --disable-pip-version-check \
    --target "$RESOURCES_DIR/backend/Lib/site-packages" \
    --platform win_amd64 \
    --python-version 311 \
    --implementation cp \
    --abi cp311 \
    --only-binary=:all: \
    --upgrade \
    -r "$ROOT_DIR/requirements-windows-cross.txt" \
    'cryptography<46' \
    'semgrep==1.170.0'

PYWIN32_PTH="$RESOURCES_DIR/backend/Lib/site-packages/pywin32.pth"
PYWIN32_TYPES_DLL="$(find "$RESOURCES_DIR/backend/Lib/site-packages" -type f -iname 'pywintypes*.dll' -print -quit)"
TZDATA_SHANGHAI="$RESOURCES_DIR/backend/Lib/site-packages/tzdata/zoneinfo/Asia/Shanghai"
[ -f "$PYWIN32_PTH" ] || { echo "Missing pywin32.pth in the bundled Windows runtime" >&2; exit 1; }
[ -n "$PYWIN32_TYPES_DLL" ] || { echo "Missing pywintypes DLL in the bundled Windows runtime" >&2; exit 1; }
[ -f "$TZDATA_SHANGHAI" ] || { echo "Missing Asia/Shanghai tzdata in the bundled Windows runtime" >&2; exit 1; }
CTRANSLATE2_PYD="$(find "$RESOURCES_DIR/backend/Lib/site-packages/ctranslate2" -type f -iname '_ext*.pyd' -print -quit)"
CTRANSLATE2_DLL="$(find "$RESOURCES_DIR/backend/Lib/site-packages/ctranslate2" -type f -iname 'ctranslate2.dll' -print -quit)"
SENTENCEPIECE_PYD="$(find "$RESOURCES_DIR/backend/Lib/site-packages/sentencepiece" -type f -iname '_sentencepiece*.pyd' -print -quit)"
OPENCC_DICTIONARY="$RESOURCES_DIR/backend/Lib/site-packages/opencc/dictionary/STCharacters.txt"
NUMPY_BINARY_LICENSE="$(find "$RESOURCES_DIR/backend/Lib/site-packages" -path '*/numpy-*.dist-info/licenses/LICENSE.txt' -type f -print -quit)"
[ -n "$CTRANSLATE2_PYD" ] || { echo "Missing CTranslate2 Windows extension in the bundled runtime" >&2; exit 1; }
[ -n "$CTRANSLATE2_DLL" ] || { echo "Missing CTranslate2 Windows DLL in the bundled runtime" >&2; exit 1; }
[ -n "$SENTENCEPIECE_PYD" ] || { echo "Missing SentencePiece Windows extension in the bundled runtime" >&2; exit 1; }
[ -f "$OPENCC_DICTIONARY" ] || { echo "Missing OpenCC dictionaries in the bundled runtime" >&2; exit 1; }
[ -n "$NUMPY_BINARY_LICENSE" ] || { echo "Missing NumPy binary notices in the bundled runtime" >&2; exit 1; }
python3 "$ROOT_DIR/scripts/validate_translation_model.py" \
    "$RESOURCES_DIR/backend/app/resources/translation-models/opus-mt-en-zh-1.9"

env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
    CARGO_HTTP_PROXY='' cargo xwin build \
    --manifest-path "$ROOT_DIR/scripts/windows-python-launcher/Cargo.toml" \
    --target x86_64-pc-windows-msvc --release
LAUNCHER="$ROOT_DIR/scripts/windows-python-launcher/target/x86_64-pc-windows-msvc/release/secflow-windows-python-launcher.exe"
[ -f "$LAUNCHER" ] || { echo "Missing Windows launcher: $LAUNCHER" >&2; exit 1; }
cp "$LAUNCHER" "$RESOURCES_DIR/backend/secflow-backend.exe"
cp "$LAUNCHER" "$RESOURCES_DIR/semgrep/secflow-semgrep.exe"
cp -R "$ROOT_DIR/config/semgrep/." "$RESOURCES_DIR/semgrep-rules/"
cp "$ROOT_DIR/licenses/THIRD-PARTY-NOTICES.txt" "$RESOURCES_DIR/licenses/THIRD-PARTY-NOTICES.txt"
cp "$ROOT_DIR/licenses/NumPy-BSD-3-Clause.txt" "$RESOURCES_DIR/licenses/NumPy-BSD-3-Clause.txt"
cp "$NUMPY_BINARY_LICENSE" "$RESOURCES_DIR/licenses/NumPy-Binary-Notices.txt"
cp "$ROOT_DIR/licenses/CTranslate2-MIT.txt" "$RESOURCES_DIR/licenses/CTranslate2-MIT.txt"
cp "$ROOT_DIR/licenses/SentencePiece-Apache-2.0.txt" "$RESOURCES_DIR/licenses/SentencePiece-Apache-2.0.txt"
cp "$ROOT_DIR/licenses/OpenCC-Python-Reimplemented-Apache-2.0.txt" "$RESOURCES_DIR/licenses/OpenCC-Python-Reimplemented-Apache-2.0.txt"
cp "$ROOT_DIR/licenses/OpenCC-Python-Reimplemented-NOTICE.txt" "$RESOURCES_DIR/licenses/OpenCC-Python-Reimplemented-NOTICE.txt"
cp "$ROOT_DIR/licenses/OPUS-MT-CC-BY-4.0.txt" "$RESOURCES_DIR/licenses/OPUS-MT-CC-BY-4.0.txt"

cd "$TAURI_DIR"
BACKEND_SHA256="$(shasum -a 256 "$RESOURCES_DIR/backend/secflow-backend.exe" | awk '{print $1}')"
TAURI_ARGS=(tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc --bundles nsis)
if [ "$EDITION" = "trial" ]; then
    TAURI_ARGS+=(--config "$TAURI_SOURCE_DIR/tauri.trial.conf.json")
fi
SECFLOW_BACKEND_SHA256="$BACKEND_SHA256" \
SECFLOW_BACKEND_PORT="$BACKEND_PORT" \
SECFLOW_TAURI_TRIAL_BUILD="$TRIAL_BUILD" \
VITE_SECFLOW_SERVER_URL="http://127.0.0.1:$BACKEND_PORT" \
VITE_SECFLOW_TRIAL_BUILD="$TRIAL_BUILD" \
CARGO_HTTP_PROXY='' pnpm "${TAURI_ARGS[@]}"

NSIS_DIR="$TAURI_SOURCE_DIR/target/x86_64-pc-windows-msvc/release/bundle/nsis"
INSTALLER="$(find "$NSIS_DIR" -maxdepth 1 -type f -name '*.exe' -exec ls -t {} + | head -n 1)"
[ -n "$INSTALLER" ] || { echo "Missing NSIS installer in $NSIS_DIR" >&2; exit 1; }
OUTPUT_DIR="${SECFLOW_WINDOWS_OUTPUT_DIR:-$ROOT_DIR/dist/windows-x86_64/$EDITION}"
mkdir -p "$OUTPUT_DIR"
FINAL_PATH="$OUTPUT_DIR/SecFlow-v$VERSION-Windows-x86_64-$EDITION_LABEL-Setup.exe"
cp "$INSTALLER" "$FINAL_PATH"
shasum -a 256 "$FINAL_PATH"
printf '%s\n' "$FINAL_PATH"
