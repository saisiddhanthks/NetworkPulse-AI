@echo off
setlocal EnableExtensions
cd /d %~dp0

echo Starting NetworkPulse AI...
if not exist backend\.venv\Scripts\python.exe (
  echo Python environment not found. Running one-time setup...
  call scripts\setup_windows.bat
  if errorlevel 1 exit /b 1
)

start "NetworkPulse AI Backend" cmd /k "cd /d "%~dp0backend" && call .venv\Scripts\activate.bat && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

echo Waiting for the engine to become ready...
set READY=
for /l %%i in (1,1,40) do (
  curl.exe -s -o NUL http://127.0.0.1:8000/api/ping >nul 2>nul
  if not errorlevel 1 set READY=1
  if defined READY goto :open
  timeout /t 1 /nobreak >nul
)

echo ERROR: Backend did not become ready within 40 seconds.
echo Check the NetworkPulse AI Backend window for the exact error.
pause
exit /b 1

:open
start "" http://127.0.0.1:8000/
echo.
echo NetworkPulse AI is online: http://127.0.0.1:8000/
echo Keep the backend window open while using the application.
echo.
exit /b 0
