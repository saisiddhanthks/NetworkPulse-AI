@echo off
setlocal EnableExtensions
cd /d %~dp0..\

echo.
echo ============================================================
echo       NETWORKPULSE AI ^| ONE-TIME WINDOWS SETUP
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python was not found. Install Python 3.11+ and enable Add Python to PATH.
  pause
  exit /b 1
)
where py >nul 2>nul
if not exist backend\.venv\Scripts\python.exe (
  echo Creating Python virtual environment...
  python -m venv backend\.venv
  if errorlevel 1 goto :fail
)

call backend\.venv\Scripts\activate.bat
python -m pip install --upgrade pip
if errorlevel 1 goto :fail
python -m pip install -r backend\requirements.txt
if errorlevel 1 goto :fail

if not exist backend\.env (
  if exist backend\.env.example copy /y backend\.env.example backend\.env >nul
)

python scripts\extract_real_data.py
if errorlevel 1 goto :fail

if not exist backend\models\xgboost_core.joblib goto :missingmodel
if not exist backend\models\lightgbm_core.joblib goto :missingmodel
if not exist backend\models\catboost_core.joblib goto :missingmodel
if not exist backend\models\anomaly_core.joblib goto :missingmodel
if not exist backend\data\event_cache.csv.gz goto :missingcache
if not exist backend\data\evaluation_results.json goto :missingeval

python -c "import xgboost,lightgbm,catboost,fastapi,pandas,sklearn,httpx; print('Python dependencies: OK')"
if errorlevel 1 goto :fail

echo.
echo SETUP COMPLETE.
echo Trained models and the CICIDS2017 evidence cache are bundled.
echo No npm install is required.
echo.
exit /b 0

:missingmodel
:missingcache
:missingeval
echo ERROR: A required artifact is missing. Re-clone the repository (Git LFS is not required) and rerun setup.
goto :fail

:fail
echo.
echo SETUP FAILED. Read the error above.
pause
exit /b 1
