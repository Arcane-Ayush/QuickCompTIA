"""Top-level orchestrator stitching together all 4 modules of the Cloud IAM Misconfiguration Detector."""

import os
import sys
import json
import argparse
import webbrowser
from typing import Dict, Any

# Ensure project root is in Python path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the orchestrator pipeline."""
    parser = argparse.ArgumentParser(
        description="CLOUD IAM MISCONFIGURATION DETECTOR - Full Pipeline Orchestrator"
    )
    parser.add_argument(
        "--input", "-i",
        default=os.path.join(PROJECT_ROOT, "sample_data", "iam_export_sample.json"),
        help="Path to AWS IAM export JSON file (default: sample_data/iam_export_sample.json)"
    )
    parser.add_argument(
        "--graph-out",
        default=os.path.join(PROJECT_ROOT, "graph_export.json"),
        help="Path to output graph_export.json (default: graph_export.json)"
    )
    parser.add_argument(
        "--findings-out",
        default=os.path.join(PROJECT_ROOT, "findings.json"),
        help="Path to output findings.json (default: findings.json)"
    )
    parser.add_argument(
        "--remediations-out",
        default=os.path.join(PROJECT_ROOT, "remediations.json"),
        help="Path to output remediations.json (default: remediations.json)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int, default=8080,
        help="Port for Dashboard UI server (default: 8080)"
    )
    parser.add_argument(
        "--no-serve",
        action="store_true",
        help="Execute pipeline and output JSON files without launching web server"
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Automatically open default browser when starting dashboard server"
    )
    return parser.parse_args()


def run_stage_1_parser(input_path: str, graph_out: str) -> None:
    """Execute Stage 1: Parser & Graph Builder (Person 1)."""
    print("\n=======================================================")
    print(" [STAGE 1] Parser & Graph Builder (Person 1)")
    print("=======================================================")
    print(f"Reading IAM export from: {input_path}")
    from parser_graph.main import run as run_parser
    run_parser(input_path, graph_out)
    print(f"Stage 1 complete -> Graph saved to: {graph_out}")


def run_stage_2_detector(graph_path: str, findings_out: str) -> Dict[str, Any]:
    """Execute Stage 2: Detection Engine & Risk Scorer (Person 2)."""
    print("\n=======================================================")
    print(" [STAGE 2] Detection Engine & Risk Scorer (Person 2)")
    print("=======================================================")
    print(f"Reading authorization graph from: {graph_path}")
    from detection_engine.detector import run_detection
    results = run_detection(graph_path, findings_out)
    findings_count = len(results.get("findings", []))
    print(f"Stage 2 complete -> Discovered {findings_count} risk finding(s). Saved to: {findings_out}")
    return results


def run_stage_3_remediator(findings_path: str, remediations_out: str) -> Dict[str, Any]:
    """Execute Stage 3: Least-Privilege Remediation Generator (Person 3)."""
    print("\n=======================================================")
    print(" [STAGE 3] Least-Privilege Remediation Generator (Person 3)")
    print("=======================================================")
    print(f"Reading risk findings from: {findings_path}")
    with open(findings_path, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    from remediation_generator.generator import RemediationGenerator
    generator = RemediationGenerator()
    remediations_data = generator.generate_remediations(findings_data)

    with open(remediations_out, "w", encoding="utf-8") as f:
        json.dump(remediations_data, f, indent=2)

    rem_count = len(remediations_data.get("remediations", []))
    print(f"Stage 3 complete -> Generated {rem_count} remediation statement(s). Saved to: {remediations_out}")
    return remediations_data


def run_stage_4_dashboard(port: int, open_browser: bool = False) -> None:
    """Execute Stage 4: Launch Interactive Dashboard Server (Person 4)."""
    print("\n=======================================================")
    print(" [STAGE 4] Launching Interactive Dashboard (Person 4)")
    print("=======================================================")
    from dashboard_ui.server import start_server
    
    url = f"http://localhost:{port}"
    print(f"Dashboard UI ready at: {url}")
    if open_browser:
        webbrowser.open(url)

    start_server(port=port)


def main() -> None:
    """Main orchestrator execution workflow."""
    args = parse_args()
    print("Starting Cloud IAM Misconfiguration Detector Pipeline...")

    # Stage 1: Parse & Build Graph
    run_stage_1_parser(args.input, args.graph_out)

    # Stage 2: Detection & Risk Scoring
    run_stage_2_detector(args.graph_out, args.findings_out)

    # Stage 3: Remediation Generation
    run_stage_3_remediator(args.findings_out, args.remediations_out)

    print("\n=======================================================")
    print(" [SUCCESS] Pipeline Completed End-to-End!")
    print("=======================================================")
    print(f"  1. Graph Export: {args.graph_out}")
    print(f"  2. Findings:     {args.findings_out}")
    print(f"  3. Remediations: {args.remediations_out}")

    # Stage 4: Dashboard Server
    if not args.no_serve:
        run_stage_4_dashboard(port=args.port, open_browser=args.open_browser)


if __name__ == "__main__":
    main()
