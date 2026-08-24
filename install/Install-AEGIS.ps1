[CmdletBinding()]
param(
    [string]$SourcePath = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "AEGIS"),
    [string]$DataRoot = (Join-Path $env:ProgramData "AEGIS"),
    [ValidateRange(1024, 65535)][int]$Port = 8765,
    [ValidateRange(10, 3600)][int]$TelemetryInterval = 30,
    [string]$LicensePath,
    [string]$LicensePublicKeyPath,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ServiceName = "AEGISNode"
$Release = "1.2.0"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated PowerShell window."
    }
}

Assert-Administrator
if ([bool]$LicensePath -xor [bool]$LicensePublicKeyPath) {
    throw "Provide both -LicensePath and -LicensePublicKeyPath, or neither."
}
$SourcePath = (Resolve-Path $SourcePath).Path
foreach ($required in @("aegis", "web", "pyproject.toml")) {
    if (-not (Test-Path (Join-Path $SourcePath $required))) {
        throw "SourcePath is not a complete AEGIS release: missing $required"
    }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
    throw "The $ServiceName service already exists. Re-run with -Force for an in-place upgrade."
}
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Milliseconds 750
}

$AppRoot = Join-Path $InstallRoot "app-$Release"
$RuntimeRoot = Join-Path $InstallRoot "runtime"
New-Item -ItemType Directory -Force -Path $AppRoot, $DataRoot | Out-Null
& icacls.exe $DataRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "AEGIS could not protect its data root." }
Copy-Item -Path (Join-Path $SourcePath "aegis") -Destination $AppRoot -Recurse -Force
Copy-Item -Path (Join-Path $SourcePath "web") -Destination $AppRoot -Recurse -Force
foreach ($file in @("pyproject.toml", "README.md", "LICENSE.txt")) {
    $candidate = Join-Path $SourcePath $file
    if (Test-Path $candidate) { Copy-Item -Path $candidate -Destination $AppRoot -Force }
}

$PythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($PythonCommand) {
    & py -3 -m venv $RuntimeRoot
} else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCommand) { throw "Python 3.10 or newer is required." }
    & python -m venv $RuntimeRoot
}

$PythonExe = Join-Path $RuntimeRoot "Scripts\python.exe"
& $PythonExe -m pip install --disable-pip-version-check cryptography==46.0.0
if ($LASTEXITCODE -ne 0) { throw "AEGIS cryptographic verifier installation failed." }
& $PythonExe -m pip install --disable-pip-version-check --no-deps --no-build-isolation -e $AppRoot
if ($LASTEXITCODE -ne 0) { throw "AEGIS runtime installation failed." }

$DatabasePath = Join-Path $DataRoot "aegis.db"
$LicenseTarget = Join-Path $DataRoot "license.json"
$LicensePublicKeyTarget = Join-Path $DataRoot "license_public_key.pem"
if ($LicensePath) {
    Copy-Item -LiteralPath (Resolve-Path $LicensePath).Path -Destination $LicenseTarget -Force
    Copy-Item -LiteralPath (Resolve-Path $LicensePublicKeyPath).Path -Destination $LicensePublicKeyTarget -Force
}
$TokenPath = Join-Path $DataRoot "console.token"
if (-not (Test-Path $TokenPath)) {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Set-Content -LiteralPath $TokenPath -Value $token -NoNewline -Encoding ascii
}
$BinaryPath = "`"$PythonExe`" -m aegis.windows_service --host 127.0.0.1 --port $Port --database `"$DatabasePath`" --telemetry-interval $TelemetryInterval --session-token-file `"$TokenPath`""
New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName "AEGIS Resident Security Node" -Description "Local-first passive telemetry, deception intelligence and analyst control plane." -StartupType Automatic | Out-Null
& sc.exe config $ServiceName start= delayed-auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service -Name $ServiceName

$Healthy = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    Start-Sleep -Milliseconds 500
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/health" -TimeoutSec 2
        if ($health.status -eq "healthy") { $Healthy = $true; break }
    } catch { }
}
if (-not $Healthy) {
    throw "The service was created but its loopback health endpoint did not become ready. Inspect the Windows Service state before retrying."
}

Write-Host "AEGIS $Release is running as $ServiceName."
Write-Host "Install the desktop extra and run 'python -m aegis.desktop' for the native AEGIS window."
Write-Warning "This Research Edition installer and Python runtime are not code-signed. Treat it as an authorized development build, not a production deployment."
