"""
exporter.py — Person 1 (Parser & Graph Builder)
Converts a NetworkX DiGraph into the graph_export.json format
defined in Section 2.1 of the build protocol.
"""

import json
import networkx as nx


def graph_to_export(G: nx.DiGraph, accounts: list[str]) -> dict:
    """
    Convert the NetworkX graph G into a dict matching the Section 2.1 schema.

    Args:
        G:        The built IAM privilege graph.
        accounts: List of AWS account ID strings present in this export.

    Returns:
        A dict with 'accounts', 'nodes', and 'edges' keys.
    """
    nodes = _export_nodes(G)
    edges = _export_edges(G)
    return {
        "accounts": sorted(set(accounts)),
        "nodes": nodes,
        "edges": edges,
    }


def write_graph_export(export_dict: dict, output_path: str) -> None:
    """Write the export dict to output_path as indented JSON."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(export_dict, fh, indent=2)
    print(f"[exporter] Wrote graph_export.json -> {output_path}")
    print(f"           Nodes: {len(export_dict['nodes'])}, Edges: {len(export_dict['edges'])}")


# ---------------------------------------------------------------------------
# Internal serializers
# ---------------------------------------------------------------------------

_VALID_NODE_TYPES = {"user", "role", "group", "policy", "resource"}
_VALID_EDGE_PERMISSIONS = {"sts:AssumeRole", "iam:PassRole", "policy_attachment", "group_membership"}


def _export_nodes(G: nx.DiGraph) -> list[dict]:
    """Serialize all graph nodes into the schema-compliant list."""
    result = []
    for node_id, data in G.nodes(data=True):
        node_type = data.get("type", "resource")
        if node_type not in _VALID_NODE_TYPES:
            node_type = "resource"

        result.append({
            "id": node_id,
            "type": node_type,
            "account_id": data.get("account_id", "unknown"),
            "name": data.get("name", node_id.split("/")[-1]),
            "attached_policies": data.get("attached_policies", []),
            "is_admin_equivalent": bool(data.get("is_admin_equivalent", False)),
        })
    return result


def _export_edges(G: nx.DiGraph) -> list[dict]:
    """Serialize all graph edges into the schema-compliant list."""
    result = []
    for source, target, data in G.edges(data=True):
        permission = data.get("permission", "policy_attachment")
        if permission not in _VALID_EDGE_PERMISSIONS:
            permission = "policy_attachment"

        condition = data.get("condition")
        # Ensure condition is either None or a plain dict (not a complex object)
        if condition is not None and not isinstance(condition, dict):
            condition = None

        result.append({
            "source": source,
            "target": target,
            "permission": permission,
            "condition": condition,
            "is_wildcard_resource": bool(data.get("is_wildcard_resource", False)),
        })
    return result
