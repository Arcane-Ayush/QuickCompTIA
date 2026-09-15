#!/usr/bin/env bash
# Shell script to run the entire Cloud IAM Misconfiguration Detector pipeline & launch UI

echo "================================================================="
echo "   Cloud IAM Misconfiguration Detector — Unified Application"
echo "================================================================="
echo ""

# Ensure dependencies are installed
pip install -r requirements.txt --quiet

# Execute full pipeline end-to-end and launch browser
python app.py --open-browser "$@"
