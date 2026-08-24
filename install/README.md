# AEGIS source-mode Windows Service package

This compatibility installer turns the AEGIS Python control plane into the
`AEGISNode` auto-start Windows Service. For the intended `.exe` product, use
`BUILD_AEGIS_EXE.bat` and the installer inside the generated Windows package.
The desktop application opens in its own native window and attaches to this
loopback service; telemetry collection continues when the window is closed.

From an elevated PowerShell window in the release directory:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install\Install-AEGIS.ps1
```

Use `-Force` to replace an existing AEGIS service with this release. Uninstall
the service without destroying telemetry or evidence:

```powershell
.\install\Uninstall-AEGIS.ps1
```

Application files and local data are removed only when the explicit
`-RemoveApplicationFiles` and `-RemoveTelemetryAndEvidence` switches are used.

This v1.2 Desktop Research Edition is not code-signed. Enterprise release requires a
signed installer/runtime, service-account hardening, ACL review, authenticated
named-user identity binding, external audit anchoring, license trust-anchor
hardening, audit-policy validation, and organization-specific approval.
