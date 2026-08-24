@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  set "AEGIS_PY=py -3"
) else (
  set "AEGIS_PY=python"
)

echo.
echo   AEGIS Desktop Edition v1.2.0
echo   Native window / local runtime / authorized threat range
echo.
%AEGIS_PY% -m aegis.desktop

if errorlevel 1 (
  echo.
  echo AEGIS could not start. Install the desktop dependency or build AEGIS.exe with BUILD_AEGIS_EXE.bat.
  pause
)
