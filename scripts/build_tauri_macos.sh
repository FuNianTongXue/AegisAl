#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$ROOT_DIR/desktop/SecFlowTauri"
TAURI_SOURCE_DIR="$TAURI_DIR/src-tauri"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
MACOS_ARCH="${SECFLOW_MACOS_ARCH:-arm64}"
TARGET_TRIPLE="${SECFLOW_TAURI_TARGET:-aarch64-apple-darwin}"
BUILD_ROOT="${SECFLOW_TAURI_BUILD_ROOT:-${TMPDIR:-/tmp}/secflow-tauri-macos-build}"
BACKEND_PORT="${SECFLOW_TAURI_BACKEND_PORT:-18781}"
TRIAL_BUILD="${SECFLOW_TAURI_TRIAL_BUILD:-0}"
TAURI_CONFIG="${SECFLOW_TAURI_CONFIG:-}"
BACKEND_BUILD_DIR="$BUILD_ROOT/backend"
SEMGREP_BUILD_DIR="$BUILD_ROOT/semgrep"
RESOURCES_DIR="$TAURI_SOURCE_DIR/resources"
RULES_PATH="${SECFLOW_SEMGREP_RULES_PATH:-$ROOT_DIR/config/semgrep}"
BACKEND_RUNTIME_DIR="$RESOURCES_DIR/backend"
BACKEND_EXECUTABLE="$BACKEND_RUNTIME_DIR/secflow-backend"
TRANSLATION_MODEL_DIR="$ROOT_DIR/app/resources/translation-models/opus-mt-en-zh-1.9"
BUNDLE_DIR="$TAURI_SOURCE_DIR/target/$TARGET_TRIPLE/release/bundle"

case "$MACOS_ARCH:$TARGET_TRIPLE" in
    arm64:aarch64-apple-darwin|x86_64:x86_64-apple-darwin) ;;
    *) echo "Unsupported architecture and target pair: $MACOS_ARCH / $TARGET_TRIPLE" >&2; exit 1 ;;
esac

PYTHON_ARCH="$($PYTHON_BIN -c 'import platform; print(platform.machine())')"
[ "$PYTHON_ARCH" = "$MACOS_ARCH" ] || {
    echo "Python architecture is $PYTHON_ARCH, expected $MACOS_ARCH: $PYTHON_BIN" >&2
    exit 1
}
for MODULE in PyInstaller semgrep semdep reportlab docx tree_sitter uvicorn xlsxwriter numpy ctranslate2 sentencepiece opencc; do
    "$PYTHON_BIN" -c "import $MODULE" >/dev/null 2>&1 || {
        echo "Missing Python module: $MODULE" >&2
        exit 1
    }
done
"$PYTHON_BIN" "$ROOT_DIR/scripts/validate_translation_model.py" "$TRANSLATION_MODEL_DIR"
[ -d "$RULES_PATH" ] || { echo "Missing offline Semgrep rules: $RULES_PATH" >&2; exit 1; }

# Tauri keeps bundles from previous product names and architectures. Remove
# legacy-branded bundles from every generated target before building the
# selected architecture so testers cannot accidentally launch an old app.
if [ -d "$TAURI_SOURCE_DIR/target" ]; then
    while IFS= read -r LEGACY_BUNDLE; do
        rm -rf "$LEGACY_BUNDLE"
    done < <(find "$TAURI_SOURCE_DIR/target" -type d -path '*/release/bundle/macos/安全智脑.app' -prune -print)
    while IFS= read -r LEGACY_DMG; do
        rm -f "$LEGACY_DMG"
    done < <(find "$TAURI_SOURCE_DIR/target" -type f -path '*/release/bundle/dmg/安全智脑_*.dmg' -print)
fi
rm -rf "$BUILD_ROOT" "$RESOURCES_DIR" "$BUNDLE_DIR"
mkdir -p "$BACKEND_BUILD_DIR" "$SEMGREP_BUILD_DIR" "$BACKEND_RUNTIME_DIR" \
    "$RESOURCES_DIR/semgrep" "$RESOURCES_DIR/semgrep-rules" "$RESOURCES_DIR/licenses"

"$PYTHON_BIN" -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --name secflow-backend \
    --paths "$ROOT_DIR" \
    --add-data "$ROOT_DIR/app/resources:app/resources" \
    --collect-all reportlab \
    --collect-all docx \
    --collect-all xlsxwriter \
    --collect-all tree_sitter \
    --collect-all tree_sitter_java \
    --collect-all tree_sitter_python \
    --collect-all tree_sitter_go \
    --collect-all tree_sitter_c \
    --collect-all tree_sitter_cpp \
    --collect-all tree_sitter_cuda \
    --collect-all tree_sitter_c_sharp \
    --collect-all tree_sitter_rust \
    --collect-all tree_sitter_solidity \
    --collect-all ctranslate2 \
    --collect-all sentencepiece \
    --collect-all opencc \
    --copy-metadata numpy \
    --copy-metadata ctranslate2 \
    --copy-metadata sentencepiece \
    --copy-metadata opencc-python-reimplemented \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.loops.asyncio \
    --hidden-import uvicorn.protocols.http.h11_impl \
    --hidden-import uvicorn.lifespan.on \
    --exclude-module psycopg \
    --exclude-module psycopg_binary \
    --distpath "$BACKEND_BUILD_DIR/dist" \
    --workpath "$BACKEND_BUILD_DIR/work" \
    --specpath "$BACKEND_BUILD_DIR" \
    "$ROOT_DIR/app/macos_backend.py"

cp -R "$BACKEND_BUILD_DIR/dist/secflow-backend/." "$BACKEND_RUNTIME_DIR/"
chmod 755 "$BACKEND_EXECUTABLE"
BUNDLED_TRANSLATION_MODEL_DIR="$(find "$BACKEND_RUNTIME_DIR" -path '*/app/resources/translation-models/opus-mt-en-zh-1.9' -type d -print -quit)"
[ -n "$BUNDLED_TRANSLATION_MODEL_DIR" ] || { echo "Bundled offline translation model is missing from the backend." >&2; exit 1; }
"$PYTHON_BIN" "$ROOT_DIR/scripts/validate_translation_model.py" "$BUNDLED_TRANSLATION_MODEL_DIR"
"$PYTHON_BIN" "$ROOT_DIR/scripts/validate_packaged_translation_runtime.py" "$BACKEND_EXECUTABLE"

if [ "${SECFLOW_SKIP_SOCKET_VALIDATION:-0}" = "1" ]; then
    echo "Skipping packaged backend socket validation because SECFLOW_SKIP_SOCKET_VALIDATION=1."
else
    "$ROOT_DIR/scripts/validate_tauri_backend_workers.sh" "$BACKEND_EXECUTABLE" "$PYTHON_BIN"
fi

SEMGREP_HIDDEN_IMPORT_ARGS=()
while IFS= read -r MODULE_NAME; do
    [ -n "$MODULE_NAME" ] && SEMGREP_HIDDEN_IMPORT_ARGS+=(--hidden-import "$MODULE_NAME")
done < <("$PYTHON_BIN" - <<'PY'
from pathlib import Path

import semdep

site_packages = Path(semdep.__file__).resolve().parent.parent
for extension in sorted(site_packages.glob("*__mypyc*.so")):
    print(extension.name.split(".", 1)[0])
PY
)
[ "${#SEMGREP_HIDDEN_IMPORT_ARGS[@]}" -gt 0 ] || {
    echo "Unable to locate Semgrep's compiled mypyc support module." >&2
    exit 1
}

"$PYTHON_BIN" -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --name secflow-semgrep \
    --collect-all semgrep \
    --collect-all semdep \
    --copy-metadata semgrep \
    "${SEMGREP_HIDDEN_IMPORT_ARGS[@]}" \
    --distpath "$SEMGREP_BUILD_DIR/dist" \
    --workpath "$SEMGREP_BUILD_DIR/work" \
    --specpath "$SEMGREP_BUILD_DIR" \
    "$ROOT_DIR/app/semgrep_runner.py"

cp -R "$SEMGREP_BUILD_DIR/dist/secflow-semgrep/." "$RESOURCES_DIR/semgrep/"
cp -R "$RULES_PATH/." "$RESOURCES_DIR/semgrep-rules/"
cp "$ROOT_DIR/licenses/THIRD-PARTY-NOTICES.txt" "$RESOURCES_DIR/licenses/THIRD-PARTY-NOTICES.txt"
cp "$ROOT_DIR/licenses/Beautiful-UI-MIT.txt" "$RESOURCES_DIR/licenses/Beautiful-UI-MIT.txt"
cp "$ROOT_DIR/licenses/NumPy-BSD-3-Clause.txt" "$RESOURCES_DIR/licenses/NumPy-BSD-3-Clause.txt"
cp "$ROOT_DIR/licenses/CTranslate2-MIT.txt" "$RESOURCES_DIR/licenses/CTranslate2-MIT.txt"
cp "$ROOT_DIR/licenses/SentencePiece-Apache-2.0.txt" "$RESOURCES_DIR/licenses/SentencePiece-Apache-2.0.txt"
cp "$ROOT_DIR/licenses/OpenCC-Python-Reimplemented-Apache-2.0.txt" "$RESOURCES_DIR/licenses/OpenCC-Python-Reimplemented-Apache-2.0.txt"
cp "$ROOT_DIR/licenses/OpenCC-Python-Reimplemented-NOTICE.txt" "$RESOURCES_DIR/licenses/OpenCC-Python-Reimplemented-NOTICE.txt"
cp "$ROOT_DIR/licenses/OPUS-MT-CC-BY-4.0.txt" "$RESOURCES_DIR/licenses/OPUS-MT-CC-BY-4.0.txt"
NUMPY_BINARY_LICENSE_PATH="$($PYTHON_BIN - <<'PY'
from importlib.metadata import distribution

package = distribution("numpy")
for entry in package.files or []:
    if str(entry).replace("\\", "/").endswith("licenses/LICENSE.txt"):
        print(package.locate_file(entry))
        break
PY
)"
[ -f "$NUMPY_BINARY_LICENSE_PATH" ] || { echo "Unable to locate the NumPy binary notices." >&2; exit 1; }
cp "$NUMPY_BINARY_LICENSE_PATH" "$RESOURCES_DIR/licenses/NumPy-Binary-Notices.txt"

while IFS= read -r PYTHON_FRAMEWORK; do
    for ALIAS in Python Resources Versions/Current; do
        [ -L "$PYTHON_FRAMEWORK/$ALIAS" ] && unlink "$PYTHON_FRAMEWORK/$ALIAS"
    done
done < <(find "$RESOURCES_DIR" -type d -name Python.framework -print)

xattr -cr "$BACKEND_RUNTIME_DIR" "$RESOURCES_DIR/semgrep" 2>/dev/null || true
if [ "${SECFLOW_SKIP_SEMGREP_VALIDATION:-0}" = "1" ]; then
    echo "Skipping packaged Semgrep runtime validation because SECFLOW_SKIP_SEMGREP_VALIDATION=1."
else
    PYTHON_BIN="$PYTHON_BIN" bash \
        "$ROOT_DIR/scripts/validate_semgrep_runtime.sh" \
        "$RESOURCES_DIR/semgrep" \
        "$RESOURCES_DIR/semgrep-rules"
fi

if [ "${SECFLOW_TAURI_PREPARE_ONLY:-0}" = "1" ]; then
    printf '%s\n' "$BACKEND_EXECUTABLE" "$RESOURCES_DIR"
    exit 0
fi

cd "$TAURI_DIR"
BACKEND_SHA256="$(shasum -a 256 "$BACKEND_EXECUTABLE" | awk '{print $1}')"
TAURI_BUILD_ARGS=(tauri build --target "$TARGET_TRIPLE" --bundles app,dmg)
if [ -n "$TAURI_CONFIG" ]; then
    TAURI_BUILD_ARGS+=(--config "$TAURI_CONFIG")
fi
SECFLOW_BACKEND_SHA256="$BACKEND_SHA256" \
SECFLOW_BACKEND_PORT="$BACKEND_PORT" \
SECFLOW_TAURI_TRIAL_BUILD="$TRIAL_BUILD" \
VITE_SECFLOW_SERVER_URL="http://127.0.0.1:$BACKEND_PORT" \
VITE_SECFLOW_TRIAL_BUILD="$TRIAL_BUILD" \
CARGO_HTTP_PROXY='' pnpm "${TAURI_BUILD_ARGS[@]}"
