@echo off
title AGENT SHIELD - Backend API (Port 8000)
echo ============================================================
echo   AGENT SHIELD: Runtime Authorization & Policy Engine
echo   Starting FastAPI Server on http://localhost:8000
echo ============================================================
echo.
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
