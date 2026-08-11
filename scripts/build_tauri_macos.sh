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

case "$MACOS_ARCH:$TARGET_TRIPLE" in
    arm64:aarch64-apple-darwin|x86_64:x86_64-apple-darwin) ;;
    *) echo "Unsupported architecture and target pair: $MACOS_ARCH / $TARGET_TRIPLE" >&2; exit 1 ;;
esac

PYTHON_ARCH="$($PYTHON_BIN -c 'import platform; print(platform.machine())')"
[ "$PYTHON_ARCH" = "$MACOS_ARCH" ] || {
    echo "Python architecture is $PYTHON_ARCH, expected $MACOS_ARCH: $PYTHON_BIN" >&2
    exit 1
}
for MODULE in PyInstaller semgrep reportlab docx tree_sitter uvicorn xlsxwriter; do
    "$PYTHON_BIN" -c "import $MODULE" >/dev/null 2>&1 || {
        echo "Missing Python module: $MODULE" >&2
        exit 1
    }
done
[ -d "$RULES_PATH" ] || { echo "Missing offline Semgrep rules: $RULES_PATH" >&2; exit 1; }

rm -rf "$BUILD_ROOT" "$RESOURCES_DIR"
mkdir -p "$BACKEND_BUILD_DIR" "$SEMGREP_BUILD_DIR" "$BACKEND_RUNTIME_DIR" \
    "$RESOURCES_DIR/semgrep" "$RESOURCES_DIR/semgrep-rules" "$RESOURCES_DIR/licenses"

"$PYTHON_BIN" -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --name secflow-backend \
    --paths "$ROOT_DIR" \
    --add-data "$ROOT_DIR/app/static:app/static" \
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

"$ROOT_DIR/scripts/validate_tauri_backend_workers.sh" "$BACKEND_EXECUTABLE" "$PYTHON_BIN"

"$PYTHON_BIN" -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --name secflow-semgrep \
    --collect-all semgrep \
    --copy-metadata semgrep \
    --distpath "$SEMGREP_BUILD_DIR/dist" \
    --workpath "$SEMGREP_BUILD_DIR/work" \
    --specpath "$SEMGREP_BUILD_DIR" \
    "$ROOT_DIR/app/semgrep_runner.py"

cp -R "$SEMGREP_BUILD_DIR/dist/secflow-semgrep/." "$RESOURCES_DIR/semgrep/"
cp -R "$RULES_PATH/." "$RESOURCES_DIR/semgrep-rules/"
cp "$ROOT_DIR/licenses/THIRD-PARTY-NOTICES.txt" "$RESOURCES_DIR/licenses/THIRD-PARTY-NOTICES.txt"

while IFS= read -r PYTHON_FRAMEWORK; do
    for ALIAS in Python Resources Versions/Current; do
        [ -L "$PYTHON_FRAMEWORK/$ALIAS" ] && unlink "$PYTHON_FRAMEWORK/$ALIAS"
    done
done < <(find "$RESOURCES_DIR" -type d -name Python.framework -print)

xattr -cr "$BACKEND_RUNTIME_DIR" "$RESOURCES_DIR/semgrep" 2>/dev/null || true
PYTHON_BIN="$PYTHON_BIN" bash \
    "$ROOT_DIR/scripts/validate_semgrep_runtime.sh" \
    "$RESOURCES_DIR/semgrep" \
    "$RESOURCES_DIR/semgrep-rules"

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
