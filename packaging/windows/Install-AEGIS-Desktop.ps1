[CmdletBinding()]
param(
    [string]$BundleRoot = $PSScriptRoot,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "AEGIS"),
    [string]$DataRoot = (Join-Path $env:ProgramData "AEGIS"),
    [ValidateRange(1024, 65535)][int]$Port = 8765,
    [ValidateRange(10, 3600)][int]$TelemetryInterval = 30,
    [string]$LicensePath,
    [string]$LicensePublicKeyPath,
    [switch]$DesktopShortcut,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ServiceName = "AEGISNode"
$Release = "1.2.0"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run the AEGIS installer as Administrator."
}
if ([bool]$LicensePath -xor [bool]$LicensePublicKeyPath) {
    throw "Provide both -LicensePath and -LicensePublicKeyPath, or neither."
}

$BundleRoot = (Resolve-Path $BundleRoot).Path
$DesktopSource = Join-Path $BundleRoot "AEGIS-Desktop"
$NodeSource = Join-Path $BundleRoot "AEGIS-Node"
foreach ($required in @((Join-Path $DesktopSource "AEGIS.exe"), (Join-Path $NodeSource "AEGISNode.exe"))) {
    if (-not (Test-Path $required)) { throw "The release package is incomplete: missing $required" }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
    throw "$ServiceName already exists. Re-run with -Force for an in-place upgrade."
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
$DesktopTarget = Join-Path $AppRoot "Desktop"
$NodeTarget = Join-Path $AppRoot "Node"
$resolvedAppRoot = [IO.Path]::GetFullPath($AppRoot)
if (-not $resolvedAppRoot.StartsWith([IO.Path]::GetFullPath($InstallRoot), [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing an unsafe application path."
}
if (Test-Path $resolvedAppRoot) { Remove-Item -LiteralPath $resolvedAppRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $DesktopTarget, $NodeTarget, $DataRoot | Out-Null
Copy-Item -Path (Join-Path $DesktopSource "*") -Destination $DesktopTarget -Recurse -Force
Copy-Item -Path (Join-Path $NodeSource "*") -Destination $NodeTarget -Recurse -Force
& icacls.exe $DataRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "AEGIS could not protect its data root." }

if ($LicensePath) {
    $ResolvedLicense = (Resolve-Path $LicensePath).Path
    $ResolvedPublicKey = (Resolve-Path $LicensePublicKeyPath).Path
    Copy-Item -LiteralPath $ResolvedLicense -Destination (Join-Path $DataRoot "license.json") -Force
    Copy-Item -LiteralPath $ResolvedPublicKey -Destination (Join-Path $DataRoot "license_public_key.pem") -Force
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
& icacls.exe $TokenPath /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "*S-1-5-32-545:R" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "AEGIS could not apply the console-token ACL." }

$NodeExe = Join-Path $NodeTarget "AEGISNode.exe"
$DatabasePath = Join-Path $DataRoot "aegis.db"
$BinaryPath = "`"$NodeExe`" --host 127.0.0.1 --port $Port --database `"$DatabasePath`" --telemetry-interval $TelemetryInterval --session-token-file `"$TokenPath`""
New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName "AEGIS Resident Security Node" -Description "Local-first defensive telemetry, deception intelligence and analyst control plane." -StartupType Automatic | Out-Null
& sc.exe config $ServiceName start= delayed-auto | Out-Null
if ($LASTEXITCODE -ne 0) { throw "AEGIS could not configure delayed service startup." }
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "AEGIS could not configure service recovery." }
Start-Service -Name $ServiceName

$Programs = [Environment]::GetFolderPath("CommonPrograms")
$ShortcutFolder = Join-Path $Programs "AEGIS"
New-Item -ItemType Directory -Force -Path $ShortcutFolder | Out-Null
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut((Join-Path $ShortcutFolder "AEGIS.lnk"))
$Shortcut.TargetPath = Join-Path $DesktopTarget "AEGIS.exe"
$Shortcut.WorkingDirectory = $DesktopTarget
$Shortcut.Description = "AEGIS Self-Learning Cyber Deception Network"
$Shortcut.Save()
if ($DesktopShortcut) {
    $Desktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
    $DesktopLink = $Shell.CreateShortcut((Join-Path $Desktop "AEGIS.lnk"))
    $DesktopLink.TargetPath = Join-Path $DesktopTarget "AEGIS.exe"
    $DesktopLink.WorkingDirectory = $DesktopTarget
    $DesktopLink.Description = "AEGIS Self-Learning Cyber Deception Network"
    $DesktopLink.Save()
}

$Healthy = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Milliseconds 500
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/health" -TimeoutSec 2
        if ($health.status -eq "healthy" -and $health.release -eq $Release) { $Healthy = $true; break }
    } catch { }
}
if (-not $Healthy) { throw "AEGISNode was installed but did not pass its loopback health check." }

Write-Host "AEGIS $Release installed successfully."
Write-Host "Launch AEGIS from the Windows Start menu."
Write-Warning "This research build is not code-signed. Production deployment requires an organization-owned signing certificate and independent validation."
