"""Matches declarative escalation rules against authorization graph nodes and edges."""

import json
from pathlib import Path
from typing import Dict, List, Optional
from detection_engine.models import Finding, GraphEdge, GraphNode, OffendingStatement
from detection_engine.narrative_generator import generate_known_pattern_narrative
from detection_engine.risk_calculator import calculate_risk, evaluate_condition_complexity


class PatternMatcher:
    """Evaluates declarative privilege escalation rules against the IAM authorization graph."""

    def __init__(self, rules_path: Optional[str] = None):
        """Initialize matcher with declarative rules loaded from JSON."""
        if rules_path is None:
            rules_path = str(Path(__file__).parent / "rules" / "iam_privesc_rules.json")
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> List[dict]:
        """Load declarative escalation rules from disk."""
        with open(self.rules_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data.get("rules", [])

    def detect_patterns(
        self,
        nodes: Dict[str, GraphNode],
        edges: List[GraphEdge],
        id_counter: int = 1,
    ) -> List[Finding]:
        """Execute pattern matching against the graph and return known_pattern findings."""
        findings: List[Finding] = []

        # Index outbound edges by source node ID for efficient query
        outbound: Dict[str, List[GraphEdge]] = {}
        for edge in edges:
            outbound.setdefault(edge.source, []).append(edge)

        for rule in self.rules:
            matched_findings = self._evaluate_rule(rule, nodes, outbound, id_counter + len(findings))
            findings.extend(matched_findings)

        return findings

    def _evaluate_rule(
        self,
        rule: dict,
        nodes: Dict[str, GraphNode],
        outbound_edges: Dict[str, List[GraphEdge]],
        start_id: int,
    ) -> List[Finding]:
        """Evaluate a single declarative rule across all principal graph nodes."""
        results: List[Finding] = []
        rule_perms = set(rule.get("required_permissions", []))
        requires_admin = rule.get("requires_admin_target", False)
        target_types = set(rule.get("target_node_types", []))
        rule_id = rule["rule_id"]

        for source_id, node in nodes.items():
            if node.is_admin_equivalent:
                # Admins already possess all privileges; we analyze non-admin escalations
                continue

            node_edges = outbound_edges.get(source_id, [])

            # Case A: Multi-permission combination (e.g. PassRole + RunInstances)
            if rule_id == "RULE-PASSRUN":
                results.extend(self._match_passrole_runinstances(rule, node, node_edges, nodes, start_id + len(results)))
                continue

            # Case B: Direct action edges matching rule permissions
            for edge in node_edges:
                if edge.permission in rule_perms:
                    target_node = nodes.get(edge.target)
                    if not target_node:
                        # Target could be an ARN not represented in node list
                        if requires_admin:
                            continue
                    else:
                        if target_types and target_node.type not in target_types:
                            continue
                        if requires_admin and not target_node.is_admin_equivalent:
                            continue

                    # Determine policy ARN associated with this edge
                    pol_arn = edge.policy_arn or (node.attached_policies[0] if node.attached_policies else f"arn:aws:iam::{node.account_id}:policy/EscalationPolicy")
                    condition_penalty = evaluate_condition_complexity(edge.condition)

                    risk_score, breakdown = calculate_risk(
                        reachability=rule.get("base_reachability", 0.9),
                        blast_radius=rule.get("base_blast_radius", 0.95),
                        exploit_triviality=rule.get("base_exploit_triviality", 0.85),
                        condition_penalty=condition_penalty,
                        hop_penalty=0.0,
                    )

                    target_display = target_node.name if target_node else edge.target.split("/")[-1]
                    narrative = generate_known_pattern_narrative(
                        template=rule.get("narrative_template", "{source} can execute {action} on {target}."),
                        source_name=node.name,
                        target_name=target_display,
                        hops=1,
                        action=edge.permission,
                    )

                    finding = Finding(
                        finding_id=f"F-{start_id + len(results):03d}",
                        type="known_pattern",
                        pattern_name=rule["pattern_name"],
                        path=[source_id, edge.target],
                        risk_score=risk_score,
                        risk_breakdown=breakdown,
                        narrative=narrative,
                        offending_statement=OffendingStatement(
                            policy_arn=pol_arn,
                            action=edge.permission,
                            resource=edge.target if not edge.is_wildcard_resource else "*",
                        ),
                    )
                    results.append(finding)

        return results

    def _match_passrole_runinstances(
        self,
        rule: dict,
        node: GraphNode,
        node_edges: List[GraphEdge],
        nodes: Dict[str, GraphNode],
        start_id: int,
    ) -> List[Finding]:
        """Detect PassRole+RunInstances combination allowing instance credential theft."""
        results: List[Finding] = []
        pass_role_edges = [e for e in node_edges if e.permission == "iam:PassRole"]
        if not pass_role_edges:
            return results

        # Check for presence of ec2:RunInstances or compute permissions
        has_compute_launch = any(
            e.permission in ("ec2:RunInstances", "ec2:*", "*:*", "*")
            for e in node_edges
        ) or any("ec2" in p.lower() or "admin" in p.lower() for p in node.attached_policies)

        # In realistic IAM datasets, PassRole to admin role is dangerous even if compute is in same or implied scope
        for pass_edge in pass_role_edges:
            target_node = nodes.get(pass_edge.target)
            is_admin_target = target_node.is_admin_equivalent if target_node else pass_edge.is_wildcard_resource
            if not is_admin_target and not pass_edge.is_wildcard_resource:
                continue

            pol_arn = pass_edge.policy_arn or (node.attached_policies[0] if node.attached_policies else f"arn:aws:iam::{node.account_id}:policy/DevPolicy")
            condition_pen = evaluate_condition_complexity(pass_edge.condition)

            risk_score, breakdown = calculate_risk(
                reachability=rule.get("base_reachability", 0.90),
                blast_radius=rule.get("base_blast_radius", 0.95),
                exploit_triviality=rule.get("base_exploit_triviality", 0.85) if has_compute_launch else 0.70,
                condition_penalty=condition_pen,
            )

            target_name = target_node.name if target_node else pass_edge.target.split("/")[-1]
            narrative = (
                f"{node.name} can become admin in 2 hops: assumes or passes privileged role "
                f"{target_name} to a compute instance (EC2) to extract admin credentials."
            )

            results.append(
                Finding(
                    finding_id=f"F-{start_id + len(results):03d}",
                    type="known_pattern",
                    pattern_name=rule["pattern_name"],
                    path=[node.id, pass_edge.target],
                    risk_score=risk_score,
                    risk_breakdown=breakdown,
                    narrative=narrative,
                    offending_statement=OffendingStatement(
                        policy_arn=pol_arn,
                        action="iam:PassRole",
                        resource="*" if pass_edge.is_wildcard_resource else pass_edge.target,
                    ),
                )
            )

        return results
