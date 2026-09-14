"""
graph_builder.py — Person 1 (Parser & Graph Builder)
Constructs a directed NetworkX graph from parsed IAM entities.
Nodes = users / roles / groups / policies / resources.
Edges = policy_attachment, group_membership, sts:AssumeRole, iam:PassRole.
Each edge carries 'permission', 'condition', and 'is_wildcard_resource'.
"""

import networkx as nx


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_graph(
    users: list[dict],
    roles: list[dict],
    groups: list[dict],
    policy_map: dict[str, dict],
    admin_map: dict[str, bool],
) -> nx.DiGraph:
    """
    Build and return the full IAM privilege graph.

    Args:
        users:      Cleaned user records from parser.extract_users()
        roles:      Cleaned role records from parser.extract_roles()
        groups:     Cleaned group records from parser.extract_groups()
        policy_map: ARN → policy record from parser.extract_policies()
        admin_map:  ARN → bool from parser.compute_is_admin_equivalent()

    Returns:
        nx.DiGraph where each node has attributes stored in the graph's
        node data and each edge has 'permission', 'condition',
        'is_wildcard_resource'.
    """
    G = nx.DiGraph()

    _add_user_nodes(G, users, admin_map)
    _add_role_nodes(G, roles, admin_map)
    _add_group_nodes(G, groups)
    _add_policy_nodes(G, policy_map)

    _add_group_membership_edges(G, users)
    _add_policy_attachment_edges(G, users, roles, groups)
    _add_assume_role_edges(G, roles)
    _add_pass_role_edges(G, users, roles, groups, policy_map)

    return G


# ---------------------------------------------------------------------------
# Node adders
# ---------------------------------------------------------------------------

def _add_user_nodes(G: nx.DiGraph, users: list[dict], admin_map: dict[str, bool]) -> None:
    """Add one node per IAM user."""
    for u in users:
        G.add_node(
            u["arn"],
            type="user",
            account_id=u["account_id"],
            name=u["name"],
            attached_policies=u["attached_policies"],
            is_admin_equivalent=admin_map.get(u["arn"], False),
        )


def _add_role_nodes(G: nx.DiGraph, roles: list[dict], admin_map: dict[str, bool]) -> None:
    """Add one node per IAM role."""
    for r in roles:
        G.add_node(
            r["arn"],
            type="role",
            account_id=r["account_id"],
            name=r["name"],
            attached_policies=r["attached_policies"],
            is_admin_equivalent=admin_map.get(r["arn"], False),
        )


def _add_group_nodes(G: nx.DiGraph, groups: list[dict]) -> None:
    """Add one node per IAM group."""
    for g in groups:
        G.add_node(
            g["arn"],
            type="group",
            account_id=g["account_id"],
            name=g["name"],
            attached_policies=g["attached_policies"],
            is_admin_equivalent=False,
        )


def _add_policy_nodes(G: nx.DiGraph, policy_map: dict[str, dict]) -> None:
    """Add one node per managed IAM policy."""
    for arn, pol in policy_map.items():
        G.add_node(
            arn,
            type="policy",
            account_id=pol["account_id"],
            name=pol["name"],
            attached_policies=[],
            is_admin_equivalent=False,
        )


# ---------------------------------------------------------------------------
# Edge adders
# ---------------------------------------------------------------------------

def _add_group_membership_edges(G: nx.DiGraph, users: list[dict]) -> None:
    """Add group_membership edges: user → group for every group the user belongs to."""
    for u in users:
        for group_name in u.get("groups", []):
            # Find the group ARN from graph nodes
            group_arn = _find_group_arn_by_name(G, group_name)
            if group_arn:
                G.add_edge(
                    u["arn"],
                    group_arn,
                    permission="group_membership",
                    condition=None,
                    is_wildcard_resource=False,
                )


def _add_policy_attachment_edges(
    G: nx.DiGraph,
    users: list[dict],
    roles: list[dict],
    groups: list[dict],
) -> None:
    """Add policy_attachment edges: principal → policy for every attached managed policy."""
    for entity in [*users, *roles, *groups]:
        for parn in entity.get("attached_policies", []):
            if G.has_node(parn):
                G.add_edge(
                    entity["arn"],
                    parn,
                    permission="policy_attachment",
                    condition=None,
                    is_wildcard_resource=False,
                )


def _add_assume_role_edges(G: nx.DiGraph, roles: list[dict]) -> None:
    """
    Add sts:AssumeRole edges derived from each role's trust policy.
    Direction: trusted_principal → role (the principal CAN assume the role).
    """
    for role in roles:
        for stmt in role.get("trust_statements", []):
            if stmt["effect"] != "Allow":
                continue
            if not _has_action(stmt["actions"], "sts:AssumeRole"):
                continue
            principals = stmt.get("principal") or []
            for principal_arn in principals:
                # Resolve AWS root ARNs to account-level (keep as-is; Detection Engine can expand)
                if G.has_node(principal_arn):
                    G.add_edge(
                        principal_arn,
                        role["arn"],
                        permission="sts:AssumeRole",
                        condition=stmt.get("condition"),
                        is_wildcard_resource="*" in stmt.get("resources", []),
                    )
                else:
                    # Add a placeholder node for external / service principals
                    G.add_node(
                        principal_arn,
                        type="resource",
                        account_id=_account_from_arn(principal_arn),
                        name=principal_arn.split(":")[-1],
                        attached_policies=[],
                        is_admin_equivalent=False,
                    )
                    G.add_edge(
                        principal_arn,
                        role["arn"],
                        permission="sts:AssumeRole",
                        condition=stmt.get("condition"),
                        is_wildcard_resource="*" in stmt.get("resources", []),
                    )


def _add_pass_role_edges(
    G: nx.DiGraph,
    users: list[dict],
    roles: list[dict],
    groups: list[dict],
    policy_map: dict[str, dict],
) -> None:
    """
    Add iam:PassRole edges for every principal whose effective policies contain
    an Allow iam:PassRole statement.

    Direction: principal → target_resource (the Resource field of the statement).
    If Resource is *, a synthetic 'wildcard-resource' node is used as the target
    and is_wildcard_resource is set True.
    """
    for entity in [*users, *roles]:
        all_stmts = list(entity.get("inline_policies", []))
        for parn in entity.get("attached_policies", []):
            pol = policy_map.get(parn)
            if pol:
                all_stmts.extend(pol["statements"])

        for stmt in all_stmts:
            if stmt["effect"] != "Allow":
                continue
            if not _has_action(stmt["actions"], "iam:PassRole"):
                continue
            for resource in stmt.get("resources", []):
                is_wildcard = resource == "*"
                target = resource if not is_wildcard else _wildcard_resource_node(G)
                if not G.has_node(target):
                    G.add_node(
                        target,
                        type="resource",
                        account_id="unknown",
                        name=target,
                        attached_policies=[],
                        is_admin_equivalent=False,
                    )
                G.add_edge(
                    entity["arn"],
                    target,
                    permission="iam:PassRole",
                    condition=stmt.get("condition"),
                    is_wildcard_resource=is_wildcard,
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_action(actions: list[str], target: str) -> bool:
    """Return True if the target action is present or covered by a wildcard."""
    target_lower = target.lower()
    for a in actions:
        a_lower = a.lower()
        if a_lower == "*" or a_lower == target_lower:
            return True
        if a_lower.endswith(":*"):
            service = a_lower.split(":")[0]
            if target_lower.startswith(service + ":"):
                return True
    return False


def _find_group_arn_by_name(G: nx.DiGraph, group_name: str) -> str | None:
    """Find the ARN of a group node by its name attribute."""
    for node, data in G.nodes(data=True):
        if data.get("type") == "group" and data.get("name") == group_name:
            return node
    return None


def _wildcard_resource_node(G: nx.DiGraph) -> str:
    """Return a stable synthetic ARN for the wildcard resource target node."""
    return "arn:aws:iam::*:resource/wildcard"


def _account_from_arn(arn: str) -> str:
    """Extract the 12-digit account ID from a full ARN string."""
    parts = arn.split(":")
    return parts[4] if len(parts) >= 5 else "unknown"

