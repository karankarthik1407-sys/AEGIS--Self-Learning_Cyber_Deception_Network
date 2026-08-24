[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "AEGIS"),
    [string]$DataRoot = (Join-Path $env:ProgramData "AEGIS"),
    [switch]$RemoveTelemetryAndEvidence
)

$ErrorActionPreference = "Stop"
$ServiceName = "AEGISNode"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run the AEGIS uninstaller as Administrator."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }
    & sc.exe delete $ServiceName | Out-Null
}

$links = @(
    (Join-Path ([Environment]::GetFolderPath("CommonPrograms")) "AEGIS"),
    (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "AEGIS.lnk")
)
foreach ($link in $links) { if (Test-Path $link) { Remove-Item -LiteralPath $link -Recurse -Force } }

$resolvedInstallRoot = [IO.Path]::GetFullPath($InstallRoot)
if ($resolvedInstallRoot -eq [IO.Path]::GetFullPath($env:ProgramFiles)) {
    throw "Refusing an unsafe InstallRoot."
}
if (Test-Path $resolvedInstallRoot) { Remove-Item -LiteralPath $resolvedInstallRoot -Recurse -Force }

if ($RemoveTelemetryAndEvidence) {
    $resolvedDataRoot = [IO.Path]::GetFullPath($DataRoot)
    if ($resolvedDataRoot -eq [IO.Path]::GetFullPath($env:ProgramData)) {
        throw "Refusing an unsafe DataRoot."
    }
    if (Test-Path $resolvedDataRoot) { Remove-Item -LiteralPath $resolvedDataRoot -Recurse -Force }
    Write-Warning "AEGIS telemetry, evidence and local keys were permanently removed."
} else {
    Write-Host "AEGIS telemetry, evidence and local keys were retained at $DataRoot"
}

Write-Host "AEGIS application files and Windows Service were removed."

