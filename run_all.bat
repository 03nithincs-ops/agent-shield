@echo off
title AGENT SHIELD - Launcher
echo ============================================================
echo   AGENT SHIELD: Every Agent. Every Action. Under Control.
echo   Launching Backend API and Frontend Dashboard...
echo ============================================================
echo.

start "Agent Shield - Backend" cmd /k "run_backend.bat"
timeout /t 3 /nobreak > nul
start "Agent Shield - Frontend" cmd /k "run_frontend.bat"

echo.
echo Both services started!
echo - Backend:  http://localhost:8000 (API Docs: http://localhost:8000/docs)
echo - Frontend: http://localhost:8501
echo.
