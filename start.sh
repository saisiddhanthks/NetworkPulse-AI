#!/usr/bin/env bash
# NetworkPulse AI - macOS / Linux launcher
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d backend/.venv ]; then
  python3 -m venv backend/.venv
  backend/.venv/bin/pip install --upgrade pip
  backend/.venv/bin/pip install -r backend/requirements-lock.txt
  [ -f backend/.env ] || cp backend/.env.example backend/.env
fi
cd backend
echo "NetworkPulse AI -> http://127.0.0.1:8000/"
exec .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
