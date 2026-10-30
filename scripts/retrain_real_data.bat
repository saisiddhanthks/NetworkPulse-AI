@echo off
setlocal
cd /d %~dp0..\
if not exist backend\.venv\Scripts\python.exe (
  echo Run setup_windows.bat first.
  pause
  exit /b 1
)
call backend\.venv\Scripts\activate.bat
python scripts\extract_real_data.py --require
if errorlevel 1 (
  pause
  exit /b 1
)
python backend\train.py
pause
