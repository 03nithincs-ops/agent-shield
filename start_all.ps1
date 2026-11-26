# Agent Shield - Launch All Services (PowerShell)
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  AGENT SHIELD - AI AGENT SECURITY CONTROL PLANE" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$baseDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Starting Python Isolation Forest ML Service (Port 8001)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$baseDir\ml-service'; & '..\.venv\Scripts\python.exe' run_ml.py"

Start-Sleep -Seconds 3

Write-Host "Starting Node.js Express Backend & Control Plane (Port 5000)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$baseDir\backend'; npm start"

Write-Host ""
Write-Host ">>> Services Launched Successfully! <<<" -ForegroundColor Green
Write-Host "Control Plane UI: http://localhost:5000" -ForegroundColor White
Write-Host "ML Service API:   http://localhost:8001/docs" -ForegroundColor White
