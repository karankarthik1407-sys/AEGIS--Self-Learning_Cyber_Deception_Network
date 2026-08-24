# AEGIS Windows desktop package

This package produces and installs two native Windows executables:

- `AEGIS-Desktop\AEGIS.exe` — the premium analyst desktop application;
- `AEGIS-Node\AEGISNode.exe` — the optional always-on defensive telemetry and
  control-plane Windows Service.

The interface is rendered inside the Windows WebView2 component. It does not
open a browser, expose an address bar, require an internet connection, or send
telemetry to a hosted website. The local API binds to loopback only. Mutating
desktop requests require a per-install session token.
Version 1.2 also requires a server-assigned operator scope, an active route
entitlement and a durable audit preflight before any mutating route executes.

## Build on Windows

From the source release, double-click `BUILD_AEGIS_EXE.bat`. The build installs
the pinned packaging dependencies into an isolated build environment, executes
the complete test suite, creates both executables, runs an embedded-runtime
smoke check, and emits a ZIP plus SHA-256 checksum in `release`.

PyInstaller builds for the operating system on which it runs. Therefore the
Windows package must be built on Windows rather than copied from a Linux build.

## Install

Extract the generated ZIP and double-click `INSTALL_AEGIS.bat`. Approve the
Windows administrator prompt. The installer adds an `AEGIS` Start-menu entry,
installs `AEGISNode` as a delayed automatic service, and keeps runtime data in
`%ProgramData%\AEGIS`.

For an offline signed evaluation, run `Install-AEGIS-Desktop.ps1` directly with
both `-LicensePath` and `-LicensePublicKeyPath`. The installer protects the
machine data root with an ACL. Never deploy the private authority key.

The executable and installer are reproducible development artifacts, but they
are not code-signed. A commercial deployment must sign the executable and
installer with an organization-controlled certificate and validate the package
on representative Windows endpoints. Enterprise release also requires an
embedded vendor trust anchor, identity-bound roles, license revocation/rotation
and externally anchored audit evidence.
