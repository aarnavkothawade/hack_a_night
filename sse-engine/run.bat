@echo off
setlocal
rem One-click launcher for Windows: double-click this file.
cd /d "%~dp0"
title SSE Engine

set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 set "PY=python"
)
if not defined PY goto nopython
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul || goto nopython

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PY% -m venv .venv || goto failed
)

echo Installing requirements - the first run takes about a minute...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || goto failed

echo.
echo SSE Engine is starting at http://localhost:5000
echo Keep this window open while you use it. Close it to stop the app.
echo.
start "" cmd /c "timeout /t 3 /nobreak >nul & start http://localhost:5000"
".venv\Scripts\python.exe" app.py
pause
exit /b 0

:nopython
echo Python 3.11 or newer was not found.
echo Install it from https://www.python.org/downloads/ and tick "Add Python to PATH",
echo then double-click run.bat again.
pause
exit /b 1

:failed
echo.
echo Setup failed. Copy the messages above and send them over for help.
pause
exit /b 1
