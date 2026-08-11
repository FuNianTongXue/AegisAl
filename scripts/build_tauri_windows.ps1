param(
    [ValidateSet("formal", "trial")]
    [string]$Edition = "formal",
    [string]$Python = "python",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$Version = "1.3.1"
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$TauriDir = Join-Path $RootDir "desktop\SecFlowTauri"
$TauriSourceDir = Join-Path $TauriDir "src-tauri"
$ResourcesDir = Join-Path $TauriSourceDir "resources"
$RulesPath = Join-Path $RootDir "config\semgrep"
$BuildRoot = Join-Path ([System.IO.Path]::GetTempPath()) "secflow-tauri-windows-$Edition"
$BackendBuildDir = Join-Path $BuildRoot "backend"
$SemgrepBuildDir = Join-Path $BuildRoot "semgrep"
$BackendRuntimeDir = Join-Path $ResourcesDir "backend"
$BackendExecutable = Join-Path $BackendRuntimeDir "secflow-backend.exe"
$TargetTriple = "x86_64-pc-windows-msvc"
$IsTrial = $Edition -eq "trial"
$BackendPort = if ($IsTrial) { "18783" } else { "18781" }
$EditionLabel = if ($IsTrial) { "Trial-7Days" } else { "Formal" }

if (-not $OutputDir) {
    $OutputDir = Join-Path $RootDir "dist\windows-x86_64\$Edition"
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "SecFlow Windows Tauri packages must be built on Windows x86_64."
}
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw "The build requires a Windows x86_64 host and x86_64 Python."
}
if (-not (Test-Path -LiteralPath $RulesPath -PathType Container)) {
    throw "Missing offline Semgrep rules: $RulesPath"
}

& $Python -c "import platform,sys; assert platform.machine().lower() in {'amd64','x86_64'}; import PyInstaller,semgrep,reportlab,docx,xlsxwriter,tree_sitter,uvicorn"
if ($LASTEXITCODE -ne 0) {
    throw "Python build dependencies are missing. Install requirements-windows.txt first."
}

Remove-Item -LiteralPath $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ResourcesDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $BackendBuildDir, $SemgrepBuildDir, $BackendRuntimeDir, (Join-Path $ResourcesDir "semgrep"), (Join-Path $ResourcesDir "semgrep-rules"), (Join-Path $ResourcesDir "licenses"), $OutputDir -Force | Out-Null

$BackendArguments = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
    "--name", "secflow-backend", "--paths", $RootDir,
    "--add-data", "$(Join-Path $RootDir 'app\static');app\static",
    "--add-data", "$(Join-Path $RootDir 'app\resources');app\resources",
    "--collect-all", "reportlab", "--collect-all", "docx", "--collect-all", "xlsxwriter",
    "--collect-all", "tree_sitter", "--collect-all", "tree_sitter_java",
    "--collect-all", "tree_sitter_python", "--collect-all", "tree_sitter_go",
    "--collect-all", "tree_sitter_c", "--collect-all", "tree_sitter_cpp",
    "--collect-all", "tree_sitter_cuda", "--collect-all", "tree_sitter_c_sharp",
    "--collect-all", "tree_sitter_rust", "--collect-all", "tree_sitter_solidity",
    "--hidden-import", "uvicorn.logging", "--hidden-import", "uvicorn.loops.asyncio",
    "--hidden-import", "uvicorn.protocols.http.h11_impl", "--hidden-import", "uvicorn.lifespan.on",
    "--exclude-module", "psycopg", "--exclude-module", "psycopg_binary",
    "--distpath", (Join-Path $BackendBuildDir "dist"), "--workpath", (Join-Path $BackendBuildDir "work"),
    "--specpath", $BackendBuildDir, (Join-Path $RootDir "app\macos_backend.py")
)
& $Python @BackendArguments
if ($LASTEXITCODE -ne 0) { throw "SecFlow backend packaging failed." }
Copy-Item -Path (Join-Path $BackendBuildDir "dist\secflow-backend\*") -Destination $BackendRuntimeDir -Recurse -Force

$SemgrepArguments = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "secflow-semgrep",
    "--collect-all", "semgrep", "--copy-metadata", "semgrep",
    "--distpath", (Join-Path $SemgrepBuildDir "dist"), "--workpath", (Join-Path $SemgrepBuildDir "work"),
    "--specpath", $SemgrepBuildDir, (Join-Path $RootDir "app\semgrep_runner.py")
)
& $Python @SemgrepArguments
if ($LASTEXITCODE -ne 0) { throw "SecFlow Semgrep packaging failed." }
Copy-Item -Path (Join-Path $SemgrepBuildDir "dist\secflow-semgrep\*") -Destination (Join-Path $ResourcesDir "semgrep") -Recurse -Force
Copy-Item -Path (Join-Path $RulesPath "*") -Destination (Join-Path $ResourcesDir "semgrep-rules") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\THIRD-PARTY-NOTICES.txt") -Destination (Join-Path $ResourcesDir "licenses\THIRD-PARTY-NOTICES.txt") -Force

$BackendHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BackendExecutable).Hash.ToLowerInvariant()
Push-Location $TauriDir
try {
    $TauriArguments = @("tauri", "build", "--target", $TargetTriple, "--bundles", "nsis")
    if ($IsTrial) { $TauriArguments += @("--config", "src-tauri/tauri.trial.conf.json") }
    $env:SECFLOW_BACKEND_SHA256 = $BackendHash
    $env:SECFLOW_BACKEND_PORT = $BackendPort
    $env:SECFLOW_TAURI_TRIAL_BUILD = if ($IsTrial) { "1" } else { "0" }
    $env:VITE_SECFLOW_SERVER_URL = "http://127.0.0.1:$BackendPort"
    $env:VITE_SECFLOW_TRIAL_BUILD = if ($IsTrial) { "1" } else { "0" }
    & pnpm @TauriArguments
    if ($LASTEXITCODE -ne 0) { throw "Tauri NSIS packaging failed." }
}
finally {
    Pop-Location
}

$NsisDir = Join-Path $TauriSourceDir "target\$TargetTriple\release\bundle\nsis"
$Installer = Get-ChildItem -LiteralPath $NsisDir -Filter "*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $Installer) { throw "No NSIS installer found in $NsisDir" }
$FinalPath = Join-Path $OutputDir "SecFlow-v$Version-Windows-x86_64-$EditionLabel-Setup.exe"
Copy-Item -LiteralPath $Installer.FullName -Destination $FinalPath -Force
Get-FileHash -Algorithm SHA256 -LiteralPath $FinalPath
Write-Host "SecFlow Windows package: $FinalPath"
