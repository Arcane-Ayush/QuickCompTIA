@echo off
REM Windows batch script to run the full Cloud IAM Misconfiguration Detector pipeline & launch UI

echo =================================================================
echo    Cloud IAM Misconfiguration Detector -- Unified Application
echo =================================================================
echo.

pip install -r requirements.txt
python app.py --open-browser %*
pause
