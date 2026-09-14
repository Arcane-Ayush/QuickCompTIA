"""
validate.py — Person 1 (Parser & Graph Builder)
Schema validation for graph_export.json and escalation-chain spot-checks.
"""

import json
import os
import sys
import jsonschema


# Path to schema file relative to repo root
_SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "schemas", "graph_export.schema.json"
)


def load_schema() -> dict:
    """Load the graph_export JSON schema from schemas/."""
    schema_path = os.path.abspath(_SCHEMA_PATH)
    with open(schema_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_graph_export(export_dict: dict) -> None:
    """
    Validate export_dict against the graph_export schema.
    Raises jsonschema.ValidationError on failure.
    """
    schema = load_schema()
    jsonschema.validate(instance=export_dict, schema=schema)
    print("[validate] graph_export.json passed schema validation OK")


def check_escalation_chains(export_dict: dict) -> dict:
    """
    Spot-check that the 3 known escalation chains from the sample data
    are represented in the graph.

    Returns a dict with chain names → bool (True = chain is present).
    """
    edges = export_dict.get("edges", [])
    nodes = {n["id"]: n for n in export_dict.get("nodes", [])}

    results = {}

    # Chain A: PassRole+RunInstances
    # dev-alice must have an iam:PassRole edge with is_wildcard_resource=True
    chain_a = any(
        e["permission"] == "iam:PassRole"
        and e["is_wildcard_resource"]
        and "dev-alice" in e["source"]
        for e in edges
    )
    results["Chain A (PassRole+RunInstances)"] = chain_a

    # Chain B: CreatePolicyVersion self-privesc
    # ci-bot must be attached to CreateVersionPolicy
    chain_b = any(
        e["permission"] == "policy_attachment"
        and "ci-bot" in e["source"]
        and "CreateVersionPolicy" in e["target"]
        for e in edges
    )
    results["Chain B (CreatePolicyVersion self-privesc)"] = chain_b

    # Chain C: Cross-account trust pivot
    # CrossAccountRole must have a sts:AssumeRole edge from account 222222222222
    chain_c = any(
        e["permission"] == "sts:AssumeRole"
        and "222222222222" in e["source"]
        and "CrossAccountRole" in e["target"]
        for e in edges
    )
    results["Chain C (Cross-account trust pivot)"] = chain_c

    # Admin-equivalent nodes check
    admin_nodes = [n["id"] for n in nodes.values() if n.get("is_admin_equivalent")]
    results["Admin-equivalent nodes present"] = len(admin_nodes) > 0

    return results


def print_chain_report(results: dict) -> None:
    """Print a human-readable escalation chain check report."""
    print("\n[validate] Escalation chain spot-check:")
    all_pass = True
    for chain, present in results.items():
        status = "[FOUND]  " if present else "[MISSING]"
        print(f"  {status}  {chain}")

        if not present:
            all_pass = False
    if all_pass:
        print("[validate] All chains detected in graph OK")
    else:
        print("[validate] WARNING: one or more chains are MISSING -- check parser logic.")
    return all_pass



if __name__ == "__main__":
    """Standalone validator: python parser_graph/validate.py graph_export.json"""
    path = sys.argv[1] if len(sys.argv) > 1 else "graph_export.json"
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    validate_graph_export(data)
    results = check_escalation_chains(data)
    ok = print_chain_report(results)
    sys.exit(0 if ok else 1)
