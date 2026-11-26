@echo off
title Agent Shield - Launch All Services
echo ========================================================
echo   AGENT SHIELD - AI AGENT SECURITY CONTROL PLANE
echo ========================================================
echo.
echo Starting Python Isolation Forest ML Service (Port 8001)...
start "Agent Shield - ML Service" cmd /k "cd /d %~dp0ml-service && ..\.venv\Scripts\python.exe run_ml.py"

timeout /t 3 /nobreak >nul

echo Starting Node.js Express Control Plane Backend (Port 5000)...
start "Agent Shield - Backend" cmd /k "cd /d %~dp0backend && npm start"

echo.
echo Services launched!
echo Control Plane UI: http://localhost:5000
echo ML Service API:   http://localhost:8001/docs
echo ========================================================
pause
