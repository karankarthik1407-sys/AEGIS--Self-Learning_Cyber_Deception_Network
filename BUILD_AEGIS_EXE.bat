@echo off
setlocal
cd /d "%~dp0"

echo.
echo   AEGIS Desktop Edition v1.2.0
echo   Building Windows executables and release package
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\windows\Build-AEGIS-Desktop.ps1"
if errorlevel 1 (
  echo.
  echo Build failed. Read the error above; no existing installation was changed.
  pause
  exit /b 1
)

echo.
echo Build complete. Open the release folder shown above.
pause
