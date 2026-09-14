"""Generic graph pathfinder discovering multi-hop paths to admin-equivalent principals."""

from typing import Dict, List, Set
import networkx as nx
from detection_engine.models import Finding, GraphEdge, GraphNode, OffendingStatement
from detection_engine.narrative_generator import generate_novel_path_narrative
from detection_engine.risk_calculator import calculate_risk, evaluate_path_reachability


class GraphPathFinder:
    """Discovers reachable multi-hop paths from non-admin principals to admin targets."""

    def __init__(self, nodes: Dict[str, GraphNode], edges: List[GraphEdge]):
        """Construct directed multigraph from provided IAM nodes and edges."""
        self.nodes = nodes
        self.edges = edges
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self) -> None:
        """Populate networkx DiGraph with nodes, attributes, and permission-bearing edges."""
        for node_id, node in self.nodes.items():
            self.graph.add_node(
                node_id,
                name=node.name,
                type=node.type,
                is_admin_equivalent=node.is_admin_equivalent,
                account_id=node.account_id,
            )

        for edge in self.edges:
            # We add directed edge; if multiple permissions between two nodes, store list
            if self.graph.has_edge(edge.source, edge.target):
                self.graph[edge.source][edge.target]["permissions"].append(edge.permission)
                self.graph[edge.source][edge.target]["edges"].append(edge)
            else:
                self.graph.add_edge(
                    edge.source,
                    edge.target,
                    permissions=[edge.permission],
                    edges=[edge],
                    primary_permission=edge.permission,
                )

    def find_novel_paths(
        self,
        known_finding_paths: Set[tuple],
        start_id: int = 1,
    ) -> List[Finding]:
        """Perform BFS/shortest path discovery from non-admin principals to admin nodes."""
        findings: List[Finding] = []
        non_admins = [n for n in self.nodes.values() if not n.is_admin_equivalent]
        admin_targets = [n for n in self.nodes.values() if n.is_admin_equivalent]

        # Valid transitive permission types enabling traversal
        actionable_permissions = {
            "sts:AssumeRole",
            "iam:PassRole",
            "policy_attachment",
            "group_membership",
        }

        for source in non_admins:
            if not self.graph.has_node(source.id):
                continue

            for target in admin_targets:
                if not self.graph.has_node(target.id) or source.id == target.id:
                    continue

                # Find all simple paths up to cutoff 4 hops
                try:
                    paths = list(nx.all_simple_paths(self.graph, source.id, target.id, cutoff=4))
                except nx.NetworkXNoPath:
                    continue

                for path in paths:
                    path_tuple = tuple(path)
                    if path_tuple in known_finding_paths:
                        continue  # Skip if already reported as a specific known pattern

                    # Build edge description steps
                    step_labels: List[str] = []
                    offending_edge: GraphEdge = None
                    valid_path = True

                    for i in range(len(path) - 1):
                        u, v = path[i], path[i + 1]
                        edge_data = self.graph.get_edge_data(u, v)
                        perms = edge_data.get("permissions", [])
                        matching_perms = [p for p in perms if p in actionable_permissions or "AssumeRole" in p or "PassRole" in p]
                        if not matching_perms:
                            # Path contains an edge that doesn't permit principal traversal
                            valid_path = False
                            break

                        u_name = self.nodes[u].name if u in self.nodes else u.split("/")[-1]
                        v_name = self.nodes[v].name if v in self.nodes else v.split("/")[-1]
                        perm_name = matching_perms[0]
                        step_labels.append(f"{u_name} uses {perm_name} on {v_name}")

                        if offending_edge is None and edge_data.get("edges"):
                            offending_edge = edge_data["edges"][0]

                    if not valid_path or not step_labels:
                        continue

                    # Mark this path tuple as discovered to avoid duplicates
                    known_finding_paths.add(path_tuple)

                    hops = len(path) - 1
                    reachability = evaluate_path_reachability(hops)
                    blast_radius = 0.95
                    exploit_triviality = max(0.4, 0.90 - (hops - 1) * 0.15)

                    risk_score, breakdown = calculate_risk(
                        reachability=reachability,
                        blast_radius=blast_radius,
                        exploit_triviality=exploit_triviality,
                    )

                    narrative = generate_novel_path_narrative(
                        path=path,
                        source_name=source.name,
                        target_name=target.name,
                        hop_labels=step_labels,
                    )

                    policy_arn = (
                        offending_edge.policy_arn
                        if offending_edge and offending_edge.policy_arn
                        else (source.attached_policies[0] if source.attached_policies else f"arn:aws:iam::{source.account_id}:policy/TraversalPolicy")
                    )
                    action = offending_edge.permission if offending_edge else "sts:AssumeRole"
                    resource = offending_edge.target if offending_edge and not offending_edge.is_wildcard_resource else "*"

                    findings.append(
                        Finding(
                            finding_id=f"F-{start_id + len(findings):03d}",
                            type="novel_path",
                            pattern_name=f"Novel multi-hop escalation path to {target.name}",
                            path=path,
                            risk_score=risk_score,
                            risk_breakdown=breakdown,
                            narrative=narrative,
                            offending_statement=OffendingStatement(
                                policy_arn=policy_arn,
                                action=action,
                                resource=resource,
                            ),
                        )
                    )

        return findings
