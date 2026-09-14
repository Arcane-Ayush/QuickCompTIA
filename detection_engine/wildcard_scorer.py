"""Detects and scores wildcard action and resource grants independent of exploitability."""

from typing import Dict, List
from detection_engine.models import Finding, GraphEdge, GraphNode, OffendingStatement
from detection_engine.narrative_generator import generate_wildcard_narrative
from detection_engine.risk_calculator import calculate_risk


class WildcardScorer:
    """Analyzes graph nodes and edges for over-permissive wildcard resources and actions."""

    def __init__(self, nodes: Dict[str, GraphNode], edges: List[GraphEdge]):
        """Initialize scorer with current IAM graph elements."""
        self.nodes = nodes
        self.edges = edges

    def score_wildcards(self, start_id: int = 1) -> List[Finding]:
        """Scan edges and policy attachments for wildcard over-permissions."""
        findings: List[Finding] = []
        seen_triples = set()

        for edge in self.edges:
            is_wildcard_res = edge.is_wildcard_resource or edge.target == "*" or ":*" in edge.target
            is_wildcard_act = edge.permission.endswith(":*") or edge.permission in ("*", "*:*")
            is_critical_perm = edge.permission in ("iam:PassRole", "sts:AssumeRole", "iam:*", "*")

            if not (is_wildcard_res or is_wildcard_act):
                continue

            triple_key = (edge.source, edge.permission, edge.target if not edge.is_wildcard_resource else "*")
            if triple_key in seen_triples:
                continue
            seen_triples.add(triple_key)

            source_node = self.nodes.get(edge.source)
            source_name = source_node.name if source_node else edge.source.split("/")[-1]
            policy_arn = (
                edge.policy_arn
                if edge.policy_arn
                else (source_node.attached_policies[0] if source_node and source_node.attached_policies else f"arn:aws:iam::111111111111:policy/OverpermissivePolicy")
            )
            resource_str = "*" if edge.is_wildcard_resource else edge.target

            # Determine risk factors based on action criticality
            if edge.permission in ("*", "*:*"):
                reachability = 0.95
                blast_radius = 1.00
                triviality = 0.95
                pattern_name = "Full Administrative Wildcard Grant (*:*)"
            elif is_critical_perm and is_wildcard_res:
                reachability = 0.90
                blast_radius = 0.95
                triviality = 0.85
                pattern_name = f"Unrestricted Wildcard Resource on Critical Action ({edge.permission})"
            elif is_wildcard_act:
                reachability = 0.85
                blast_radius = 0.80
                triviality = 0.80
                pattern_name = f"Service-Wide Wildcard Action ({edge.permission})"
            else:
                reachability = 0.80
                blast_radius = 0.70
                triviality = 0.75
                pattern_name = f"Wildcard Resource Over-Permission ({edge.permission})"

            risk_score, breakdown = calculate_risk(
                reachability=reachability,
                blast_radius=blast_radius,
                exploit_triviality=triviality,
            )

            narrative = generate_wildcard_narrative(
                principal_name=source_name,
                action=edge.permission,
                resource=resource_str,
                policy_arn=policy_arn,
            )

            findings.append(
                Finding(
                    finding_id=f"F-{start_id + len(findings):03d}",
                    type="wildcard_overpermission",
                    pattern_name=pattern_name,
                    path=[edge.source],
                    risk_score=risk_score,
                    risk_breakdown=breakdown,
                    narrative=narrative,
                    offending_statement=OffendingStatement(
                        policy_arn=policy_arn,
                        action=edge.permission,
                        resource=resource_str,
                    ),
                )
            )

        return findings
