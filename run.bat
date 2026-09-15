@echo off
REM Windows batch script to run the full Cloud IAM Misconfiguration Detector pipeline & launch UI

echo =================================================================
echo    Cloud IAM Misconfiguration Detector -- Unified Application
echo =================================================================
echo.

pip install -r requirements.txt
python main.py %*
python dashboard_ui\server.py --port 8080
pause
