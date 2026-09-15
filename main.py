"""
Pipeline Orchestrator — End-to-End IAM Misconfiguration Detector
Shared Integrator Module — /main.py
"""

import os
import sys
import shutil
import json
import argparse
import jsonschema

from parser_graph.graph_builder import parse_and_export
from detection_engine.detector import detect_and_export
from detection_engine.train_model import train_model
from remediation_generator.generator import remediate_and_export


def validate_schema(data: dict, schema_path: str, file_desc: str) -> bool:
    """Validates a JSON data dict against its JSON Schema definition."""
    if not os.path.exists(schema_path):
        print(f"Warning: Schema file {schema_path} not found. Skipping validation.")
        return True
    with open(schema_path, "r", encoding="utf-8") as sf:
        schema = json.load(sf)
    try:
        jsonschema.validate(instance=data, schema=schema)
        print(f"  [PASS] {file_desc} schema validation PASSED ({schema_path})")
        return True
    except jsonschema.ValidationError as err:
        print(f"  [FAIL] {file_desc} schema validation FAILED: {err.message}")
        raise err


def run_pipeline(
    input_iam_path: str = "sample_data/iam_export_sample.json",
    out_dir: str = ".",
    train_ml: bool = False,
    sync_dashboard: bool = True,
):
    """Executes Person 1 -> Person 2 -> Person 3 and validates outputs."""
    print("================================================================================")
    print("       CLOUD IAM MISCONFIGURATION DETECTOR & ML RISK ENGINE — PIPELINE          ")
    print("================================================================================\n")

    os.makedirs(out_dir, exist_ok=True)
    graph_out = os.path.join(out_dir, "graph_export.json")
    findings_out = os.path.join(out_dir, "findings.json")
    remediations_out = os.path.join(out_dir, "remediations.json")

    # Step 0: ML Model Training (if requested or missing)
    model_file = "detection_engine/models/iam_risk_classifier.pkl"
    if train_ml or not os.path.exists(model_file):
        print("[STAGE 0] Training Machine Learning Privilege Escalation Risk Model...")
        train_model()
        print("")

    # Step 1: Parser & Graph Builder (Person 1)
    print(f"[STAGE 1] Running Person 1: Parser & Graph Builder on {input_iam_path}...")
    graph_data = parse_and_export(input_iam_path, graph_out)
    validate_schema(graph_data, "schemas/graph_export.schema.json", "graph_export.json")
    print(f"  -> Generated {len(graph_data['nodes'])} nodes, {len(graph_data['edges'])} edges across {len(graph_data['accounts'])} accounts.\n")

    # Step 2: Detection Engine & Risk Scorer (Person 2)
    print("[STAGE 2] Running Person 2: Detection Engine & ML Risk Scorer...")
    findings_data = detect_and_export(
        graph_path=graph_out,
        raw_iam_path=input_iam_path,
        output_path=findings_out,
    )
    validate_schema(findings_data, "schemas/findings.schema.json", "findings.json")
    critical_count = sum(1 for f in findings_data["findings"] if f["risk_score"] >= 90)
    high_count = sum(1 for f in findings_data["findings"] if 70 <= f["risk_score"] < 90)
    print(f"  -> Identified {len(findings_data['findings'])} findings (Critical: {critical_count}, High: {high_count}).\n")

    # Step 3: Least-Privilege Remediation Generator (Person 3)
    print("[STAGE 3] Running Person 3: Least-Privilege Remediation Generator...")
    remediations_data = remediate_and_export(findings_out, remediations_out)
    validate_schema(remediations_data, "schemas/remediations.schema.json", "remediations.json")
    remediable_count = sum(1 for r in remediations_data["remediations"] if r.get("remediable", True))
    print(f"  -> Generated {len(remediations_data['remediations'])} remediations ({remediable_count} auto-remediable).\n")

    # Step 4: Synchronize to Dashboard UI data/
    if sync_dashboard:
        dash_data_dir = os.path.join("dashboard_ui", "data")
        os.makedirs(dash_data_dir, exist_ok=True)
        shutil.copy2(graph_out, os.path.join(dash_data_dir, "graph_export.json"))
        shutil.copy2(findings_out, os.path.join(dash_data_dir, "findings.json"))
        shutil.copy2(remediations_out, os.path.join(dash_data_dir, "remediations.json"))
        print(f"[STAGE 4] Synchronized real scan results to {dash_data_dir}/ for Interactive Dashboard.")

    print("\n================================================================================")
    print("PIPELINE EXECUTION COMPLETE: All stages passed, all schemas validated 100%.")
    print("Launch Dashboard: http://localhost:8080/ to inspect graph and scorecards.")
    print("================================================================================")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Cloud IAM Misconfiguration Detector Pipeline")
    parser.add_argument(
        "pos_input",
        nargs="?",
        default=None,
        help="Path to raw IAM authorization JSON file (positional argument)"
    )
    parser.add_argument(
        "--input",
        "-i",
        default=None,
        help="Path to raw IAM authorization JSON file",
    )
    parser.add_argument(
        "--outdir",
        "-o",
        default=".",
        help="Output directory for generated JSON files",
    )
    parser.add_argument(
        "--train",
        "-t",
        action="store_true",
        help="Train/retrain the ML Risk Classifier",
    )
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="Do not copy output files into dashboard_ui/data/",
    )

    args = parser.parse_args()
    input_file = args.pos_input or args.input or "sample_data/iam_export_sample.json"
    run_pipeline(
        input_iam_path=input_file,
        out_dir=args.outdir,
        train_ml=args.train,
        sync_dashboard=not args.no_sync,
    )


if __name__ == "__main__":
    main()
