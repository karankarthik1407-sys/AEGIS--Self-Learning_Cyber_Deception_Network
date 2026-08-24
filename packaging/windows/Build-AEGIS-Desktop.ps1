[CmdletBinding()]
param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "AEGIS Windows executables must be built on Windows."
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$BuildRoot = Join-Path $ProjectRoot ".aegis-build\windows"
$VenvRoot = Join-Path $BuildRoot "venv"
$WorkRoot = Join-Path $BuildRoot "pyinstaller"
$StageRoot = Join-Path $BuildRoot "stage"
$ReleaseRoot = Join-Path $ProjectRoot "release"
$ReleaseName = "AEGIS-Desktop-v1.2.0-win64"

$PyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
if ($PyLauncher) {
    if (-not (Test-Path $VenvRoot)) { & py.exe -3 -m venv $VenvRoot }
} else {
    $PythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $PythonCommand) { throw "Python 3.10 or newer is required to build AEGIS." }
    if (-not (Test-Path $VenvRoot)) { & $PythonCommand.Source -m venv $VenvRoot }
}

$PythonExe = Join-Path $VenvRoot "Scripts\python.exe"
& $PythonExe -c "import struct,sys; sys.exit(0 if struct.calcsize('P') == 8 else 1)"
if ($LASTEXITCODE -ne 0) { throw "AEGIS win64 requires a 64-bit Python build." }
& $PythonExe -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot "requirements-desktop.txt")
if ($LASTEXITCODE -ne 0) { throw "Desktop build dependencies could not be installed." }
& $PythonExe -m pip install --disable-pip-version-check --no-deps -e $ProjectRoot
if ($LASTEXITCODE -ne 0) { throw "AEGIS could not be installed into the build environment." }

if (-not $SkipTests) {
    Push-Location $ProjectRoot
    try { & $PythonExe -m unittest discover -s tests -v }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "AEGIS tests failed; executable packaging was stopped." }
}

foreach ($path in @($WorkRoot, $StageRoot)) {
    $full = [IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith([IO.Path]::GetFullPath($BuildRoot), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing an unsafe build cleanup path: $full"
    }
    if (Test-Path $full) { Remove-Item -LiteralPath $full -Recurse -Force }
}
New-Item -ItemType Directory -Force -Path $WorkRoot, $StageRoot, $ReleaseRoot | Out-Null

& $PythonExe -m PyInstaller --clean --noconfirm --distpath $StageRoot --workpath $WorkRoot (Join-Path $PSScriptRoot "AEGIS-Desktop.spec")
if ($LASTEXITCODE -ne 0) { throw "AEGIS.exe packaging failed." }
& $PythonExe -m PyInstaller --clean --noconfirm --distpath $StageRoot --workpath $WorkRoot (Join-Path $PSScriptRoot "AEGIS-Node.spec")
if ($LASTEXITCODE -ne 0) { throw "AEGISNode.exe packaging failed." }

$DesktopExe = Join-Path $StageRoot "AEGIS-Desktop\AEGIS.exe"
$NodeExe = Join-Path $StageRoot "AEGIS-Node\AEGISNode.exe"
foreach ($required in @($DesktopExe, $NodeExe)) {
    if (-not (Test-Path $required)) { throw "Expected executable was not produced: $required" }
}

$SmokeRoot = Join-Path $BuildRoot "smoke-data"
& $DesktopExe --headless-check --standalone --data-root $SmokeRoot
if ($LASTEXITCODE -ne 0) { throw "The packaged AEGIS desktop runtime failed its headless smoke check." }

foreach ($file in @("Install-AEGIS-Desktop.ps1", "Uninstall-AEGIS-Desktop.ps1", "INSTALL_AEGIS.bat", "README.md")) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $StageRoot -Force
}
Copy-Item -LiteralPath (Join-Path $ProjectRoot "LICENSE.txt") -Destination $StageRoot -Force

$ZipPath = Join-Path $ReleaseRoot "$ReleaseName.zip"
if (Test-Path $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
Compress-Archive -Path (Join-Path $StageRoot "*") -DestinationPath $ZipPath -CompressionLevel Optimal
$Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $ReleaseRoot "$ReleaseName.sha256") -Value "$Hash  $ReleaseName.zip" -Encoding ascii

Write-Host ""
Write-Host "AEGIS Windows desktop package created:"
Write-Host $ZipPath
Write-Host "SHA-256: $Hash"
