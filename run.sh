#!/usr/bin/env bash
# Shell script to run the entire Cloud IAM Misconfiguration Detector pipeline & launch UI

echo "================================================================="
echo "   Cloud IAM Misconfiguration Detector — Unified Application"
echo "================================================================="
echo ""

pip install -r requirements.txt --quiet
python main.py "$@"
python dashboard_ui/server.py --port 8080
