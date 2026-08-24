#!/usr/bin/env bash
set -euo pipefail

RUNTIME_PATH="${1:-}"
RULES_PATH="${2:-}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

fail() {
    echo "Invalid Semgrep runtime: $*" >&2
    exit 1
}

[ -d "$RUNTIME_PATH" ] || fail "runtime directory does not exist: $RUNTIME_PATH"
[ -e "$RULES_PATH" ] || fail "offline rules do not exist: $RULES_PATH"
CLI="$RUNTIME_PATH/secflow-semgrep"
[ -x "$CLI" ] || fail "missing executable: $CLI"

"$PYTHON_BIN" - "$RUNTIME_PATH" <<'PY' || fail "runtime contains a symbolic link outside its root"
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
for path in root.rglob("*"):
    if not path.is_symlink():
        continue
    try:
        path.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, ValueError):
        print(f"External or broken link: {path}", file=sys.stderr)
        raise SystemExit(1)
PY

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/secflow-semgrep-validate.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT
mkdir -p "$TMP_ROOT/home" "$TMP_ROOT/tmp" "$TMP_ROOT/poison-bin" "$TMP_ROOT/src"
for COMMAND_NAME in semgrep pysemgrep semgrep-core; do
    cat > "$TMP_ROOT/poison-bin/$COMMAND_NAME" <<'SH'
#!/bin/sh
echo "Packaged Semgrep attempted to execute an external CLI: $0" >&2
exit 97
SH
    chmod 755 "$TMP_ROOT/poison-bin/$COMMAND_NAME"
done

CLI_GUARD=()
if [ -x /usr/bin/sandbox-exec ]; then
    cat > "$TMP_ROOT/no-homebrew.sb" <<'SB'
(version 1)
(allow default)
(deny file-read* (subpath "/opt/homebrew"))
(deny process-exec (subpath "/opt/homebrew"))
SB
    CLI_GUARD=(/usr/bin/sandbox-exec -f "$TMP_ROOT/no-homebrew.sb")
fi

run_cli() {
    env -i \
        PATH="$TMP_ROOT/poison-bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        HOME="$TMP_ROOT/home" \
        TMPDIR="$TMP_ROOT/tmp" \
        LANG="en_US.UTF-8" \
        SEMGREP_SETTINGS_FILE="$TMP_ROOT/home/settings.yml" \
        SEMGREP_SEND_METRICS="off" \
        SEMGREP_ENABLE_VERSION_CHECK="0" \
        PYINSTALLER_RESET_ENVIRONMENT="1" \
        "${CLI_GUARD[@]}" \
        "$CLI" "$@"
}

EXPECTED_VERSION="$($PYTHON_BIN - "$RUNTIME_PATH" <<'PY'
from importlib.metadata import PathDistribution
from pathlib import Path
import sys

root = Path(sys.argv[1]) / "_internal"
metadata_dirs = sorted(root.glob("semgrep-*.dist-info"))
if len(metadata_dirs) != 1:
    raise SystemExit(f"expected one bundled Semgrep distribution, found {len(metadata_dirs)}")
print(PathDistribution(metadata_dirs[0]).version)
PY
)" || fail "cannot read bundled Semgrep version metadata"
VERSION="$(run_cli --version 2>/dev/null)" || fail "isolated CLI cannot start"
printf '%s\n' "$VERSION" | grep -Fx "$EXPECTED_VERSION" >/dev/null || \
    fail "CLI version '$VERSION' does not match bundled version '$EXPECTED_VERSION'"

cat > "$TMP_ROOT/src/Demo.java" <<'JAVA'
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    String command = request.getParameter("command");
    Runtime.getRuntime().exec(command);
  }
}
JAVA

if [ -d "$RULES_PATH" ]; then
cat > "$TMP_ROOT/src/demo.py" <<'PYTHON'
import os
from flask import request
command = request.args.get("command")
os.system(command)
PYTHON
cat > "$TMP_ROOT/src/demo.go" <<'GO'
package demo
import ("net/http"; "os/exec")
func run(request *http.Request) { command := request.URL.Query().Get("command"); _ = exec.Command(command).Run() }
GO
cat > "$TMP_ROOT/src/demo.c" <<'C'
#include <stdlib.h>
int main(int argc, char **argv) { return argc > 1 ? system(argv[1]) : 1; }
C
cat > "$TMP_ROOT/src/demo.cpp" <<'CPP'
#include <fstream>
int main(int argc, char **argv) { std::ifstream input; if (argc > 1) input.open(argv[1]); return 0; }
CPP
cat > "$TMP_ROOT/src/demo.rs" <<'RUST'
use std::process::Command;
fn main() { let command = std::env::var("COMMAND").unwrap(); let _ = Command::new(command).status(); }
RUST
cat > "$TMP_ROOT/src/demo.sol" <<'SOLIDITY'
pragma solidity ^0.8.20;
contract Demo { address owner; function run() external { require(tx.origin == owner, "owner"); } }
SOLIDITY
fi

run_cli scan \
    --config "$RULES_PATH" \
    --json-output "$TMP_ROOT/results.json" \
    --dataflow-traces \
    --metrics=off \
    --disable-version-check \
    --no-git-ignore \
    --project-root "$TMP_ROOT/src" \
    "$TMP_ROOT/src" >/dev/null 2>&1 || fail "multi-language validation scan failed"

"$PYTHON_BIN" - "$TMP_ROOT/results.json" "$RULES_PATH" "$EXPECTED_VERSION" <<'PY' || fail "AST/CFG/DFG rules did not return the expected findings"
import json
from pathlib import Path
import sys

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("version") != sys.argv[3]:
    print(
        f"Scan used Semgrep {payload.get('version')!r}, expected bundled {sys.argv[3]!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)
rules = {str(item.get("check_id") or "") for item in payload.get("results") or []}
expected = {"secflow.java.command-injection"}
if Path(sys.argv[2]).is_dir():
    expected.update(
        {
            "secflow.python.command-injection",
            "secflow.go.command-injection",
            "secflow.c-cpp.command-injection",
            "secflow.cpp.path-traversal",
            "secflow.rust.command-injection",
            "secflow.solidity.tx-origin-authorization",
        }
    )
missing = sorted(item for item in expected if not any(rule.endswith(item) for rule in rules))
if missing:
    print("Missing rules: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY

echo "Validated Semgrep $VERSION with offline multi-language AST/CFG/DFG rules."
