@echo off
setlocal
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$process = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0Install-AEGIS-Desktop.ps1"" -BundleRoot ""%~dp0"" -DesktopShortcut'; exit $process.ExitCode"
if errorlevel 1 (
  echo AEGIS installation did not complete.
  pause
  exit /b 1
)

echo AEGIS installation completed.
pause
