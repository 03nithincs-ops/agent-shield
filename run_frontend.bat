@echo off
title AGENT SHIELD - Frontend Dashboard (Port 8501)
echo ============================================================
echo   AGENT SHIELD: Security Dashboard & Simulation Center
echo   Starting Streamlit App on http://localhost:8501
echo ============================================================
echo.
python -m streamlit run frontend/app.py
pause
