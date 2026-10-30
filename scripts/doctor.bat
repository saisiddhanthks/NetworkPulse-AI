@echo off
setlocal
cd /d %~dp0..\
echo NETWORKPULSE AI SYSTEM CHECK
echo ------------------------------
where python >nul 2>nul && echo Python: OK || echo Python: MISSING
if exist backend\.venv\Scripts\python.exe (echo Virtualenv: OK) else (echo Virtualenv: MISSING)
if exist backend\.env (echo Backend .env: PRESENT) else (echo Backend .env: MISSING)
if exist backend\data\event_cache.csv.gz (echo Evidence cache: OK) else (echo Evidence cache: MISSING)
if exist backend\data\raw\cicids2017_real_data.tar.xz (echo Raw CICIDS2017 archive: OK) else (echo Raw CICIDS2017 archive: not present - only needed for retraining)
if exist backend\models\xgboost_core.joblib (echo XGBoost: OK) else (echo XGBoost: MISSING)
if exist backend\models\lightgbm_core.joblib (echo LightGBM: OK) else (echo LightGBM: MISSING)
if exist backend\models\catboost_core.joblib (echo CatBoost: OK) else (echo CatBoost: MISSING)
if exist backend\models\anomaly_core.joblib (echo Autoencoder/IF: OK) else (echo Autoencoder/IF: MISSING)
if exist frontend\app.js (echo Frontend: OK) else (echo Frontend: MISSING)
echo.
if exist backend\.venv\Scripts\python.exe (
  call backend\.venv\Scripts\python.exe backend\tests\smoke_test.py
) else (
  echo Run scripts\setup_windows.bat first.
)
pause
