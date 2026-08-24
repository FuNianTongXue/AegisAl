param(
    [ValidateSet("formal", "trial")]
    [string]$Edition = "formal",
    [string]$Python = "python",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$TauriDir = Join-Path $RootDir "desktop\SecFlowTauri"
$Version = (Get-Content -LiteralPath (Join-Path $TauriDir "package.json") -Raw | ConvertFrom-Json).version
if (-not $Version) { throw "Unable to read client version from desktop\SecFlowTauri\package.json" }
$TauriSourceDir = Join-Path $TauriDir "src-tauri"
$ResourcesDir = Join-Path $TauriSourceDir "resources"
$RulesPath = Join-Path $RootDir "config\semgrep"
$TranslationModelDir = Join-Path $RootDir "app\resources\translation-models\opus-mt-en-zh-1.9"
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
    throw "神盾 Windows Tauri packages must be built on Windows x86_64."
}
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw "The build requires a Windows x86_64 host and x86_64 Python."
}
if (-not (Test-Path -LiteralPath $RulesPath -PathType Container)) {
    throw "Missing offline Semgrep rules: $RulesPath"
}

& $Python -c "import platform,sys; assert platform.machine().lower() in {'amd64','x86_64'}; import PyInstaller,semgrep,reportlab,docx,xlsxwriter,tree_sitter,uvicorn,pywintypes,numpy,ctranslate2,sentencepiece,opencc; from zoneinfo import ZoneInfo; ZoneInfo('Asia/Shanghai')"
if ($LASTEXITCODE -ne 0) {
    throw "Python build dependencies are missing. Install requirements-windows.txt first."
}
& $Python (Join-Path $RootDir "scripts\validate_translation_model.py") $TranslationModelDir
if ($LASTEXITCODE -ne 0) { throw "Offline translation model validation failed." }

Remove-Item -LiteralPath $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ResourcesDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $BackendBuildDir, $SemgrepBuildDir, $BackendRuntimeDir, (Join-Path $ResourcesDir "semgrep"), (Join-Path $ResourcesDir "semgrep-rules"), (Join-Path $ResourcesDir "licenses"), $OutputDir -Force | Out-Null

$BackendArguments = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
    "--name", "secflow-backend", "--paths", $RootDir,
    "--add-data", "$(Join-Path $RootDir 'app\resources');app\resources",
    "--collect-all", "reportlab", "--collect-all", "docx", "--collect-all", "xlsxwriter",
    "--collect-all", "tree_sitter", "--collect-all", "tree_sitter_java",
    "--collect-all", "tree_sitter_python", "--collect-all", "tree_sitter_go",
    "--collect-all", "tree_sitter_c", "--collect-all", "tree_sitter_cpp",
    "--collect-all", "tree_sitter_cuda", "--collect-all", "tree_sitter_c_sharp",
    "--collect-all", "tree_sitter_rust", "--collect-all", "tree_sitter_solidity",
    "--collect-all", "tzdata",
    "--collect-all", "ctranslate2", "--collect-all", "sentencepiece", "--collect-all", "opencc",
    "--copy-metadata", "numpy",
    "--copy-metadata", "ctranslate2", "--copy-metadata", "sentencepiece",
    "--copy-metadata", "opencc-python-reimplemented",
    "--hidden-import", "uvicorn.logging", "--hidden-import", "uvicorn.loops.asyncio",
    "--hidden-import", "uvicorn.protocols.http.h11_impl", "--hidden-import", "uvicorn.lifespan.on",
    "--exclude-module", "psycopg", "--exclude-module", "psycopg_binary",
    "--distpath", (Join-Path $BackendBuildDir "dist"), "--workpath", (Join-Path $BackendBuildDir "work"),
    "--specpath", $BackendBuildDir, (Join-Path $RootDir "app\macos_backend.py")
)
& $Python @BackendArguments
if ($LASTEXITCODE -ne 0) { throw "神盾 backend packaging failed." }
Copy-Item -Path (Join-Path $BackendBuildDir "dist\secflow-backend\*") -Destination $BackendRuntimeDir -Recurse -Force
$BundledTranslationManifest = Get-ChildItem -LiteralPath $BackendRuntimeDir -Filter "manifest.json" -File -Recurse |
    Where-Object { $_.FullName.Replace('\', '/') -like "*/app/resources/translation-models/opus-mt-en-zh-1.9/manifest.json" } |
    Select-Object -First 1
if (-not $BundledTranslationManifest) { throw "Bundled offline translation model is missing." }
& $Python (Join-Path $RootDir "scripts\validate_translation_model.py") $BundledTranslationManifest.Directory.FullName
if ($LASTEXITCODE -ne 0) { throw "Bundled offline translation model validation failed." }

$SemgrepArguments = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "secflow-semgrep",
    "--collect-all", "semgrep", "--copy-metadata", "semgrep",
    "--distpath", (Join-Path $SemgrepBuildDir "dist"), "--workpath", (Join-Path $SemgrepBuildDir "work"),
    "--specpath", $SemgrepBuildDir, (Join-Path $RootDir "app\semgrep_runner.py")
)
& $Python @SemgrepArguments
if ($LASTEXITCODE -ne 0) { throw "神盾 Semgrep packaging failed." }
Copy-Item -Path (Join-Path $SemgrepBuildDir "dist\secflow-semgrep\*") -Destination (Join-Path $ResourcesDir "semgrep") -Recurse -Force
Copy-Item -Path (Join-Path $RulesPath "*") -Destination (Join-Path $ResourcesDir "semgrep-rules") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\THIRD-PARTY-NOTICES.txt") -Destination (Join-Path $ResourcesDir "licenses\THIRD-PARTY-NOTICES.txt") -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\Beautiful-UI-MIT.txt") -Destination (Join-Path $ResourcesDir "licenses\Beautiful-UI-MIT.txt") -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\NumPy-BSD-3-Clause.txt") -Destination (Join-Path $ResourcesDir "licenses\NumPy-BSD-3-Clause.txt") -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\CTranslate2-MIT.txt") -Destination (Join-Path $ResourcesDir "licenses\CTranslate2-MIT.txt") -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\SentencePiece-Apache-2.0.txt") -Destination (Join-Path $ResourcesDir "licenses\SentencePiece-Apache-2.0.txt") -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\OpenCC-Python-Reimplemented-Apache-2.0.txt") -Destination (Join-Path $ResourcesDir "licenses\OpenCC-Python-Reimplemented-Apache-2.0.txt") -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\OpenCC-Python-Reimplemented-NOTICE.txt") -Destination (Join-Path $ResourcesDir "licenses\OpenCC-Python-Reimplemented-NOTICE.txt") -Force
Copy-Item -LiteralPath (Join-Path $RootDir "licenses\OPUS-MT-CC-BY-4.0.txt") -Destination (Join-Path $ResourcesDir "licenses\OPUS-MT-CC-BY-4.0.txt") -Force
$NumpyBinaryLicense = (& $Python -c "from importlib.metadata import distribution; package=distribution('numpy'); print(next(str(package.locate_file(entry)) for entry in package.files or [] if str(entry).replace('\\','/').endswith('licenses/LICENSE.txt')))").Trim()
if (-not (Test-Path -LiteralPath $NumpyBinaryLicense)) { throw "Unable to locate the NumPy binary notices." }
Copy-Item -LiteralPath $NumpyBinaryLicense -Destination (Join-Path $ResourcesDir "licenses\NumPy-Binary-Notices.txt") -Force

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
$FinalPath = Join-Path $OutputDir "神盾-AegisAl-v$Version-Windows-x86_64-$EditionLabel-Setup.exe"
Copy-Item -LiteralPath $Installer.FullName -Destination $FinalPath -Force
Get-FileHash -Algorithm SHA256 -LiteralPath $FinalPath
Write-Host "神盾 AegisAl Windows package: $FinalPath"
