"""app.py — Top-level orchestrator wrapper for the Cloud IAM Misconfiguration Detector."""

import os
import sys
import argparse
import webbrowser

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from main import run_pipeline
from dashboard_ui.server import start_server


def main():
    """Execute pipeline and launch dashboard UI."""
    parser = argparse.ArgumentParser(description="Cloud IAM Misconfiguration Detector Pipeline")
    parser.add_argument("--input", "-i", default="sample_data/iam_export_sample.json", help="Path to raw IAM JSON export")
    parser.add_argument("--outdir", "-o", default=".", help="Output directory for generated JSON files")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Port for dashboard UI server (default: 8080)")
    parser.add_argument("--no-serve", action="store_true", help="Do not launch dashboard server")
    parser.add_argument("--open-browser", action="store_true", help="Automatically open browser")

    args = parser.parse_args()

    # Step 1-3: Run Pipeline
    run_pipeline(input_iam_path=args.input, out_dir=args.outdir)

    # Step 4: Launch UI Server
    if not args.no_serve:
        url = f"http://localhost:{args.port}"
        print(f"\n[Dashboard UI] Serving interface at: {url}")
        if args.open_browser:
            webbrowser.open(url)
        start_server(port=args.port)


if __name__ == "__main__":
    main()
