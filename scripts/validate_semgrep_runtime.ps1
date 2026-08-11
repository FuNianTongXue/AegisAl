param(
    [Parameter(Mandatory = $true)][string]$RuntimePath,
    [Parameter(Mandatory = $true)][string]$RulesPath
)

$ErrorActionPreference = "Stop"
$Cli = Join-Path $RuntimePath "secflow-semgrep.exe"
if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) {
    throw "Missing Semgrep executable: $Cli"
}
if (-not (Test-Path -LiteralPath $RulesPath)) {
    throw "Missing offline Semgrep rules: $RulesPath"
}

$Version = (& $Cli --version 2>$null | Select-Object -First 1).Trim()
if ($LASTEXITCODE -ne 0 -or $Version -notmatch '^\d+\.\d+\.\d+') {
    throw "Packaged Semgrep CLI did not return a valid version."
}

$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("secflow-semgrep-validate-" + [guid]::NewGuid())
$SourceRoot = Join-Path $TempRoot "src"
$ResultPath = Join-Path $TempRoot "results.json"
New-Item -ItemType Directory -Path $SourceRoot -Force | Out-Null
try {
    @"
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    String command = request.getParameter("command");
    Runtime.getRuntime().exec(command);
  }
}
"@ | Set-Content -LiteralPath (Join-Path $SourceRoot "Demo.java") -Encoding utf8
    @"
import os
from flask import request
command = request.args.get("command")
os.system(command)
"@ | Set-Content -LiteralPath (Join-Path $SourceRoot "demo.py") -Encoding utf8
    @"
package demo
import (`"net/http`"; `"os/exec`")
func run(request *http.Request) { command := request.URL.Query().Get(`"command`"); _ = exec.Command(command).Run() }
"@ | Set-Content -LiteralPath (Join-Path $SourceRoot "demo.go") -Encoding utf8
    @"
#include <stdlib.h>
int main(int argc, char **argv) { return argc > 1 ? system(argv[1]) : 1; }
"@ | Set-Content -LiteralPath (Join-Path $SourceRoot "demo.c") -Encoding utf8
    @"
#include <fstream>
int main(int argc, char **argv) { std::ifstream input; if (argc > 1) input.open(argv[1]); return 0; }
"@ | Set-Content -LiteralPath (Join-Path $SourceRoot "demo.cpp") -Encoding utf8
    @"
use std::process::Command;
fn main() { let command = std::env::var(`"COMMAND`").unwrap(); let _ = Command::new(command).status(); }
"@ | Set-Content -LiteralPath (Join-Path $SourceRoot "demo.rs") -Encoding utf8
    @"
pragma solidity ^0.8.20;
contract Demo { address owner; function run() external { require(tx.origin == owner, `"owner`"); } }
"@ | Set-Content -LiteralPath (Join-Path $SourceRoot "demo.sol") -Encoding utf8

    $env:SEMGREP_SEND_METRICS = "off"
    $env:SEMGREP_ENABLE_VERSION_CHECK = "0"
    & $Cli scan `
        --config $RulesPath `
        --json-output $ResultPath `
        --dataflow-traces `
        --metrics=off `
        --disable-version-check `
        --no-git-ignore `
        --project-root $SourceRoot `
        $SourceRoot | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ResultPath)) {
        throw "Packaged Semgrep multi-language validation scan failed."
    }

    $Payload = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    $ExpectedRules = @(
        "secflow.java.command-injection",
        "secflow.python.command-injection",
        "secflow.go.command-injection",
        "secflow.c-cpp.command-injection",
        "secflow.cpp.path-traversal",
        "secflow.rust.command-injection",
        "secflow.solidity.tx-origin-authorization"
    )
    foreach ($ExpectedRule in $ExpectedRules) {
        $Expected = @($Payload.results | Where-Object { $_.check_id -like "*$ExpectedRule" })
        if ($Expected.Count -eq 0) {
            throw "Packaged Semgrep did not return expected finding: $ExpectedRule"
        }
    }
}
finally {
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Validated Semgrep $Version with offline multi-language security rules."
