[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "AEGIS"),
    [string]$DataRoot = (Join-Path $env:ProgramData "AEGIS"),
    [switch]$RemoveApplicationFiles,
    [switch]$RemoveTelemetryAndEvidence
)

$ErrorActionPreference = "Stop"
$ServiceName = "AEGISNode"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell window."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }
    & sc.exe delete $ServiceName | Out-Null
    Write-Host "Removed Windows Service: $ServiceName"
} else {
    Write-Host "The $ServiceName service was not installed."
}

if ($RemoveApplicationFiles) {
    if ([string]::IsNullOrWhiteSpace($InstallRoot) -or $InstallRoot -eq $env:ProgramFiles) {
        throw "Refusing an unsafe InstallRoot."
    }
    if (Test-Path $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
    Write-Host "Removed application files: $InstallRoot"
}
if ($RemoveTelemetryAndEvidence) {
    if ([string]::IsNullOrWhiteSpace($DataRoot) -or $DataRoot -eq $env:ProgramData) {
        throw "Refusing an unsafe DataRoot."
    }
    if (Test-Path $DataRoot) { Remove-Item -LiteralPath $DataRoot -Recurse -Force }
    Write-Warning "Removed local telemetry, evidence, and the per-install pseudonymization key: $DataRoot"
} else {
    Write-Host "Retained local telemetry, evidence, and pseudonymization material at $DataRoot"
}
