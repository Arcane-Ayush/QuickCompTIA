"""
main.py — Person 1 (Parser & Graph Builder) — standalone entry point.

Usage:
    python parser_graph/main.py
    python parser_graph/main.py --input sample_data/iam_export_sample.json --output graph_export.json

Runs the full parse → build → export → validate pipeline on the given input file
and writes graph_export.json to the output path.
"""

import argparse
import sys
import os

# Allow running from repo root: `python parser_graph/main.py`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser_graph.parser import (
    load_iam_export,
    extract_users,
    extract_roles,
    extract_groups,
    extract_policies,
    compute_is_admin_equivalent,
)
from parser_graph.graph_builder import build_graph
from parser_graph.exporter import graph_to_export, write_graph_export
from parser_graph.validate import validate_graph_export, check_escalation_chains, print_chain_report


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Person 1 — IAM Parser & Graph Builder"
    )
    parser.add_argument(
        "--input",
        default="sample_data/iam_export_sample.json",
        help="Path to the GetAccountAuthorizationDetails-style IAM export JSON (default: sample_data/iam_export_sample.json)",
    )
    parser.add_argument(
        "--output",
        default="graph_export.json",
        help="Output path for graph_export.json (default: graph_export.json)",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip schema validation and chain checks after export",
    )
    return parser.parse_args()


def run(input_path: str, output_path: str, validate: bool = True) -> dict:
    """
    Full pipeline: load → parse → build graph → export → validate.

    Returns the export dict (useful when called programmatically from app.py).
    """
    print(f"[main] Loading IAM export from: {input_path}")
    raw = load_iam_export(input_path)

    print("[main] Extracting entities...")
    users = extract_users(raw)
    roles = extract_roles(raw)
    groups = extract_groups(raw)
    policy_map = extract_policies(raw)

    print(f"[main]   Users:    {len(users)}")
    print(f"[main]   Roles:    {len(roles)}")
    print(f"[main]   Groups:   {len(groups)}")
    print(f"[main]   Policies: {len(policy_map)}")

    # Collect all accounts found in the data
    accounts = set()
    for entity in [*users, *roles, *groups]:
        accounts.add(entity["account_id"])
    for pol in policy_map.values():
        accounts.add(pol["account_id"])
    accounts.discard("unknown")

    print("[main] Computing admin-equivalence...")
    all_principal_arns = [u["arn"] for u in users] + [r["arn"] for r in roles]
    admin_map = compute_is_admin_equivalent(
        all_principal_arns, users, roles, groups, policy_map
    )
    admin_count = sum(1 for v in admin_map.values() if v)
    print(f"[main]   Admin-equivalent principals: {admin_count}")

    print("[main] Building graph...")
    G = build_graph(users, roles, groups, policy_map, admin_map)
    print(f"[main]   Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    print("[main] Exporting to JSON...")
    export_dict = graph_to_export(G, list(accounts))
    write_graph_export(export_dict, output_path)

    if validate:
        print("[main] Validating output...")
        validate_graph_export(export_dict)
        results = check_escalation_chains(export_dict)
        print_chain_report(results)

    print(f"\n[main] DONE. Output written to: {output_path}")
    return export_dict


if __name__ == "__main__":
    args = parse_args()
    run(
        input_path=args.input,
        output_path=args.output,
        validate=not args.no_validate,
    )
