"""Main detection engine coordinator executing pattern matching, path finding, and wildcard analysis."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from detection_engine.models import Finding, GraphEdge, GraphNode
from detection_engine.path_finder import GraphPathFinder
from detection_engine.pattern_matcher import PatternMatcher
from detection_engine.wildcard_scorer import WildcardScorer

PathOrStr = Union[Path, str, None]


def parse_graph_export(data: Dict[str, Any]) -> Tuple[Dict[str, GraphNode], List[GraphEdge]]:
    """Parse graph JSON matching Section 2.1 schema into typed nodes and edges."""
    nodes: Dict[str, GraphNode] = {}
    for n in data.get("nodes", []):
        node = GraphNode(
            id=n["id"],
            type=n["type"],
            account_id=n.get("account_id", ""),
            name=n.get("name", n["id"].split("/")[-1]),
            attached_policies=n.get("attached_policies", []),
            is_admin_equivalent=n.get("is_admin_equivalent", False),
            metadata=n.get("metadata", {}),
        )
        nodes[node.id] = node

    edges: List[GraphEdge] = []
    for e in data.get("edges", []):
        edge = GraphEdge(
            source=e["source"],
            target=e["target"],
            permission=e["permission"],
            condition=e.get("condition"),
            is_wildcard_resource=e.get("is_wildcard_resource", False),
            policy_arn=e.get("policy_arn"),
        )
        edges.append(edge)

    return nodes, edges


def run_detection(
    input_graph_path: Union[Path, str],
    output_findings_path: PathOrStr = None,
    rules_path: PathOrStr = None,
) -> Dict[str, Any]:
    """Execute complete detection pipeline and output findings adhering to Section 2.2 schema."""
    with open(input_graph_path, "r", encoding="utf-8") as f:
        graph_data = json.load(f)

    nodes, edges = parse_graph_export(graph_data)

    all_findings: List[Finding] = []

    # 1. Declarative Known Pattern Matcher
    rules_file = str(rules_path) if rules_path else None
    pattern_matcher = PatternMatcher(rules_path=rules_file)
    known_findings = pattern_matcher.detect_patterns(nodes, edges, id_counter=1)
    all_findings.extend(known_findings)

    # 2. Generic Graph Pathfinder (BFS / Dijkstra)
    known_paths = {tuple(f.path) for f in known_findings}
    path_finder = GraphPathFinder(nodes, edges)
    novel_findings = path_finder.find_novel_paths(known_paths, start_id=len(all_findings) + 1)
    all_findings.extend(novel_findings)

    # 3. Wildcard / Over-permission Scorer
    wildcard_scorer = WildcardScorer(nodes, edges)
    wildcard_findings = wildcard_scorer.score_wildcards(start_id=len(all_findings) + 1)
    all_findings.extend(wildcard_findings)

    # Renumber findings cleanly for stable sequential IDs
    for idx, finding in enumerate(all_findings, start=1):
        finding.finding_id = f"F-{idx:03d}"

    result_payload = {
        "findings": [f.to_dict() for f in all_findings]
    }

    if output_findings_path:
        out_p = Path(output_findings_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as out_f:
            json.dump(result_payload, out_f, indent=2)

    return result_payload


def main() -> None:
    """CLI entry point for running the detection engine standalone."""
    parser = argparse.ArgumentParser(
        description="IAM Misconfiguration & Privilege Escalation Detection Engine (Person 2)"
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to input graph_export.json (Section 2.1 contract)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="findings.json",
        help="Path to write findings.json (Section 2.2 contract)",
    )
    parser.add_argument(
        "--rules",
        "-r",
        default=None,
        help="Custom path to declarative rules JSON file",
    )

    args = parser.parse_args()
    try:
        results = run_detection(args.input, args.output, args.rules)
        count = len(results.get("findings", []))
        print(f"[SUCCESS] Detection completed. {count} finding(s) generated at: {args.output}")
    except Exception as exc:
        print(f"[ERROR] Detection engine failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
