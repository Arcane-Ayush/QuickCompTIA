"""CLI entry point for running the Remediation Generator standalone."""

import sys
import os
import json
import argparse
from typing import Dict, Any
from .generator import RemediationGenerator


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the remediation generator script."""
    parser = argparse.ArgumentParser(description="CLOUD IAM MISCONFIGURATION DETECTOR - Remediation Generator")
    parser.add_argument(
        "--input", "-i",
        default=os.path.join(os.path.dirname(__file__), "sample_findings.json"),
        help="Path to input findings.json file (default: remediation_generator/sample_findings.json)"
    )
    parser.add_argument(
        "--output", "-o",
        default=os.path.join(os.path.dirname(__file__), "remediations.json"),
        help="Path to output remediations.json file (default: remediation_generator/remediations.json)"
    )
    parser.add_argument(
        "--usage-data", "-u",
        default=None,
        help="Optional path to CloudTrail usage data JSON for usage-grounded trimming"
    )
    return parser.parse_args()


def load_json_file(file_path: str) -> Dict[str, Any]:
    """Load and parse JSON file from specified path."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found at: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_file(file_path: str, data: Dict[str, Any]) -> None:
    """Write data dictionary to JSON file at specified path."""
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main() -> None:
    """Run remediation generator CLI pipeline."""
    args = parse_args()

    print(f"[Person 3 - Remediation Generator] Reading findings from: {args.input}")
    findings_data = load_json_file(args.input)

    usage_data = None
    if args.usage_data and os.path.exists(args.usage_data):
        print(f"[Person 3 - Remediation Generator] Loading CloudTrail usage data from: {args.usage_data}")
        usage_data = load_json_file(args.usage_data)

    generator = RemediationGenerator(usage_data=usage_data)
    remediations_data = generator.generate_remediations(findings_data)

    save_json_file(args.output, remediations_data)
    print(f"[Person 3 - Remediation Generator] Successfully generated {len(remediations_data.get('remediations', []))} remediation(s).")
    print(f"[Person 3 - Remediation Generator] Saved output to: {args.output}")


if __name__ == "__main__":
    main()
