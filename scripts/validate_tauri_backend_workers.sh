#!/usr/bin/env bash
set -euo pipefail

BACKEND_PATH="${1:?usage: validate_tauri_backend_workers.sh BACKEND_PATH [PYTHON_BIN]}"
PYTHON_BIN="${2:-python3}"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/secflow-backend-workers.XXXXXX")"
PORT="$($PYTHON_BIN -c 'import socket; sock = socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()')"
BACKEND_PID=""

cleanup() {
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$TEMP_DIR/data"
SECFLOW_DATA_DIR="$TEMP_DIR/data" \
SECFLOW_STORAGE_MASTER_KEY="packaged-worker-regression-key" \
SECFLOW_DISABLE_BATCH_SCHEDULER="1" \
PYTHONUNBUFFERED="1" \
    "$BACKEND_PATH" \
        --host 127.0.0.1 \
        --port "$PORT" \
        --parent-pid "$$" \
        >"$TEMP_DIR/backend.log" 2>&1 &
BACKEND_PID="$!"

if ! "$PYTHON_BIN" - "$PORT" <<'PY'
import json
import sys
import time
import urllib.request

port = int(sys.argv[1])
url = f"http://127.0.0.1:{port}/health"
deadline = time.monotonic() + 30
last_error = "backend did not answer"
while time.monotonic() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            payload = json.load(response)
        execution = payload.get("task_execution") or {}
        configured = int(execution.get("configured_workers") or 0)
        running = int(execution.get("running_workers") or 0)
        if execution.get("mode") == "external-process" and configured == 2 and running == configured:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            raise SystemExit(0)
        last_error = f"unexpected task execution status: {execution}"
    except Exception as exc:
        last_error = str(exc)
    time.sleep(0.25)
raise SystemExit(last_error)
PY
then
    cat "$TEMP_DIR/backend.log" >&2
    exit 1
fi
