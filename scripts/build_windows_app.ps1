param(
    [string]$Python = "python",
    [string]$OutputDir = "",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDir) {
    $OutputDir = Join-Path $RootDir "dist\windows"
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
$BuildDir = Join-Path ([System.IO.Path]::GetTempPath()) "secflow-windows-build"
$AppBuildDir = Join-Path $BuildDir "app"
$SemgrepBuildDir = Join-Path $BuildDir "semgrep"
$AppDir = Join-Path $OutputDir "SecFlow-Trial-7Days"
$RulesPath = Join-Path $RootDir "config\semgrep"
$ZipPath = Join-Path $OutputDir "SecFlow-Windows-x64-Trial-7Days.zip"
$InstallerPath = Join-Path $OutputDir "SecFlow-Windows-x64-Trial-7Days-Setup.exe"

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "The Windows app must be built on Windows. PyInstaller cannot cross-compile it."
}
if (-not (Test-Path -LiteralPath $RulesPath -PathType Container)) {
    throw "Missing offline Semgrep rules: $RulesPath"
}

& $Python -c "import PyInstaller, reportlab, semgrep, tree_sitter, tree_sitter_java, tree_sitter_python, tree_sitter_go, tree_sitter_c, tree_sitter_cpp, tree_sitter_cuda, tree_sitter_c_sharp, tree_sitter_rust, tree_sitter_solidity, webview"
if ($LASTEXITCODE -ne 0) {
    throw "Build dependencies are missing. Run: python -m pip install -r requirements-windows.txt"
}

Remove-Item -LiteralPath $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $AppDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$AppArguments = @(
    "-m", "PyInstaller",
    "--noconfirm", "--clean", "--onedir", "--windowed",
    "--name", "SecFlow",
    "--paths", $RootDir,
    "--add-data", "$(Join-Path $RootDir 'app\static');app\static",
    "--add-data", "$(Join-Path $RootDir 'app\resources');app\resources",
    "--collect-all", "reportlab",
    "--collect-all", "tree_sitter",
    "--collect-all", "tree_sitter_java",
    "--collect-all", "tree_sitter_python",
    "--collect-all", "tree_sitter_go",
    "--collect-all", "tree_sitter_c",
    "--collect-all", "tree_sitter_cpp",
    "--collect-all", "tree_sitter_cuda",
    "--collect-all", "tree_sitter_c_sharp",
    "--collect-all", "tree_sitter_rust",
    "--collect-all", "tree_sitter_solidity",
    "--collect-all", "webview",
    "--hidden-import", "uvicorn.logging",
    "--hidden-import", "uvicorn.loops.asyncio",
    "--hidden-import", "uvicorn.protocols.http.h11_impl",
    "--hidden-import", "uvicorn.lifespan.on",
    "--hidden-import", "webview.platforms.edgechromium",
    "--exclude-module", "psycopg",
    "--exclude-module", "psycopg_binary",
    "--distpath", (Join-Path $AppBuildDir "dist"),
    "--workpath", (Join-Path $AppBuildDir "work"),
    "--specpath", $AppBuildDir,
    (Join-Path $RootDir "app\windows_app.py")
)
& $Python @AppArguments
if ($LASTEXITCODE -ne 0) { throw "SecFlow Windows packaging failed." }

$SemgrepArguments = @(
    "-m", "PyInstaller",
    "--noconfirm", "--clean", "--onedir",
    "--name", "secflow-semgrep",
    "--collect-all", "semgrep",
    "--copy-metadata", "semgrep",
    "--distpath", (Join-Path $SemgrepBuildDir "dist"),
    "--workpath", (Join-Path $SemgrepBuildDir "work"),
    "--specpath", $SemgrepBuildDir
)
$TomliMypycModule = (& $Python -c "from importlib.metadata import distribution; print(next((str(entry).split('.')[0] for entry in distribution('tomli').files or [] if '__mypyc' in str(entry)), ''))").Trim()
if ($TomliMypycModule) {
    $SemgrepArguments += @("--hidden-import", $TomliMypycModule)
}
$SemgrepArguments += (Join-Path $RootDir "app\semgrep_runner.py")
& $Python @SemgrepArguments
if ($LASTEXITCODE -ne 0) { throw "Semgrep Windows packaging failed." }

Copy-Item -LiteralPath (Join-Path $AppBuildDir "dist\SecFlow") -Destination $AppDir -Recurse
Copy-Item -LiteralPath (Join-Path $SemgrepBuildDir "dist\secflow-semgrep") -Destination (Join-Path $AppDir "semgrep") -Recurse
New-Item -ItemType Directory -Path (Join-Path $AppDir "semgrep-rules") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $AppDir "licenses") -Force | Out-Null
Copy-Item -Path (Join-Path $RulesPath "*") -Destination (Join-Path $AppDir "semgrep-rules") -Recurse
Copy-Item -LiteralPath (Join-Path $RootDir "LICENSE") -Destination (Join-Path $AppDir "LICENSE")
Copy-Item -LiteralPath (Join-Path $RootDir "NOTICE") -Destination (Join-Path $AppDir "NOTICE")
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\D3-ISC.txt") -Destination (Join-Path $AppDir "licenses\D3-ISC.txt")
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\D3-Sankey-BSD-3-Clause.txt") -Destination (Join-Path $AppDir "licenses\D3-Sankey-BSD-3-Clause.txt")
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\THIRD-PARTY-NOTICES.txt") -Destination (Join-Path $AppDir "licenses\THIRD-PARTY-NOTICES.txt")

$LicenseLocator = @"
from importlib.metadata import distribution
import sys
package = distribution(sys.argv[1])
suffixes = tuple(sys.argv[2:])
for entry in package.files or []:
    if str(entry).replace('\\', '/').endswith(suffixes):
        print(package.locate_file(entry))
        break
"@
$SemgrepLicense = (& $Python -c $LicenseLocator "semgrep" "licenses/LICENSE" "LICENSE").Trim()
$TreeSitterLicense = (& $Python -c $LicenseLocator "tree-sitter" "licenses/LICENSE" "LICENSE").Trim()
if (-not (Test-Path -LiteralPath $SemgrepLicense)) { throw "Unable to locate the Semgrep license." }
if (-not (Test-Path -LiteralPath $TreeSitterLicense)) { throw "Unable to locate the Tree-sitter license." }
Copy-Item -LiteralPath $SemgrepLicense -Destination (Join-Path $AppDir "licenses\Semgrep-LGPL-2.1.txt")
Copy-Item -LiteralPath $TreeSitterLicense -Destination (Join-Path $AppDir "licenses\Tree-sitter-MIT.txt")
foreach ($Grammar in @("java", "python", "go", "c", "cpp", "cuda", "c-sharp", "rust", "solidity")) {
    $GrammarLicense = (& $Python -c $LicenseLocator "tree-sitter-$Grammar" "licenses/LICENSE" "LICENSE").Trim()
    if (-not (Test-Path -LiteralPath $GrammarLicense)) { throw "Unable to locate the Tree-sitter $Grammar license." }
    Copy-Item -LiteralPath $GrammarLicense -Destination (Join-Path $AppDir "licenses\Tree-sitter-$Grammar-MIT.txt")
}

& (Join-Path $AppDir "SecFlow.exe") --self-test
if ($LASTEXITCODE -ne 0) { throw "Packaged SecFlow self-test failed." }
& (Join-Path $RootDir "scripts\validate_semgrep_runtime.ps1") `
    -RuntimePath (Join-Path $AppDir "semgrep") `
    -RulesPath (Join-Path $AppDir "semgrep-rules")

Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
Compress-Archive -LiteralPath $AppDir -DestinationPath $ZipPath -CompressionLevel Optimal

if (-not $SkipInstaller) {
    $MakeNsis = Get-Command "makensis.exe" -ErrorAction SilentlyContinue
    if (-not $MakeNsis) {
        throw "NSIS is required for the setup executable. Install it or pass -SkipInstaller."
    }
    Remove-Item -LiteralPath $InstallerPath -Force -ErrorAction SilentlyContinue
    & $MakeNsis.Source "/DAPP_DIR=$AppDir" "/DOUTPUT_FILE=$InstallerPath" (Join-Path $RootDir "windows\installer.nsi")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $InstallerPath)) {
        throw "NSIS installer packaging failed."
    }
}

Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath
if (Test-Path -LiteralPath $InstallerPath) {
    Get-FileHash -Algorithm SHA256 -LiteralPath $InstallerPath
}
Write-Host "Windows trial package output: $OutputDir"
