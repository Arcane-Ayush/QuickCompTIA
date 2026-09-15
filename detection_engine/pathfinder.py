"""
Pathfinder Module — NetworkX Graph Traversal for Attack Paths and Reachability
Person 2 Module — /detection_engine/pathfinder.py
"""

from typing import Any, Dict, List, Optional, Set
import networkx as nx


class IAMPathfinder:
    """Finds directed attack escalation paths to administrator-equivalent nodes."""

    def __init__(self, graph_dict: Dict[str, Any]):
        """Initializes pathfinder from graph_export dict."""
        self.graph_dict = graph_dict
        self.nx_graph = nx.DiGraph()
        self._build_nx_graph()
        self.admin_nodes: Set[str] = {
            n["id"] for n in graph_dict.get("nodes", []) if n.get("is_admin_equivalent", False)
        }

    def _build_nx_graph(self) -> None:
        """Constructs in-memory NetworkX DiGraph."""
        for n in self.graph_dict.get("nodes", []):
            self.nx_graph.add_node(n["id"], **n)

        for e in self.graph_dict.get("edges", []):
            self.nx_graph.add_edge(e["source"], e["target"], **e)

    def find_paths_to_admin(self, source_arn: str) -> List[List[str]]:
        """Finds all shortest paths from source principal to any admin node."""
        if source_arn not in self.nx_graph or source_arn in self.admin_nodes:
            return []

        discovered_paths = []
        for target in self.admin_nodes:
            if target in self.nx_graph and nx.has_path(self.nx_graph, source_arn, target):
                try:
                    for path in nx.all_shortest_paths(self.nx_graph, source_arn, target):
                        discovered_paths.append(path)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        return discovered_paths

    def get_shortest_distance_to_admin(self, source_arn: str) -> int:
        """Returns the hop distance to closest admin node (or 99 if unreachable)."""
        paths = self.find_paths_to_admin(source_arn)
        if not paths:
            return 99
        return min(len(p) - 1 for p in paths)

    def compute_blast_radius(self, source_arn: str) -> int:
        """Calculates total number of downstream reachable nodes from source."""
        if source_arn not in self.nx_graph:
            return 0
        descendants = nx.descendants(self.nx_graph, source_arn)
        return len(descendants)

    def find_all_novel_escalation_paths(self, known_path_prefixes: List[List[str]]) -> List[Dict[str, Any]]:
        """Identifies attack paths to admin that are not covered by known rule prefixes."""
        novel_findings = []
        seen_paths = set()

        for n in self.graph_dict.get("nodes", []):
            src_id = n["id"]
            if n.get("is_admin_equivalent", False) or n.get("type") not in ["user", "role"]:
                continue

            paths = self.find_paths_to_admin(src_id)
            for path in paths:
                path_tuple = tuple(path)
                if path_tuple in seen_paths:
                    continue
                seen_paths.add(path_tuple)

                # Check if this exact path is already matched by a known rule
                is_known = False
                for known_p in known_path_prefixes:
                    if len(path) >= len(known_p) and path[:len(known_p)] == known_p:
                        is_known = True
                        break

                if not is_known and len(path) > 1:
                    hops = len(path) - 1
                    reachability = round(max(0.4, 1.0 - (hops * 0.15)), 2)
                    blast = round(min(1.0, (self.compute_blast_radius(src_id) + 5) / 20.0), 2)
                    exploit = round(max(0.5, 0.9 - (hops * 0.1)), 2)

                    novel_findings.append({
                        "path": path,
                        "reachability": reachability,
                        "blast_radius": blast,
                        "exploit_triviality": exploit,
                        "source_arn": src_id,
                        "target_arn": path[-1],
                    })

        return novel_findings
