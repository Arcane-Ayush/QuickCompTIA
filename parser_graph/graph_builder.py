"""
Graph Builder Module — NetworkX Directed IAM Graph Construction & Export
Person 1 Module — /parser_graph/graph_builder.py
"""

import json
import re
from typing import Any, Dict, List, Optional, Set
import networkx as nx

from .parser import IAMParser, NormalizedStatement


def extract_account_id(arn: str) -> str:
    """Extracts the 12-digit AWS account ID from an ARN, defaulting to 111111111111."""
    match = re.search(r":(\d{12}):", arn)
    return match.group(1) if match else "111111111111"


class IAMGraphBuilder:
    """Constructs a directed graph representing IAM principals, relations, and permissions."""

    def __init__(self, parser: IAMParser):
        """Initializes builder with an IAMParser instance."""
        self.parser = parser
        self.graph = nx.DiGraph()
        self.accounts: Set[str] = set()

    def build_graph(self) -> nx.DiGraph:
        """Constructs and returns the directed NetworkX graph."""
        # 1. Add Users
        for u in self.parser.users:
            arn = u["Arn"]
            acc = extract_account_id(arn)
            self.accounts.add(acc)
            is_admin = self.parser.is_admin_equivalent(u)
            attached = [p["PolicyArn"] for p in u.get("AttachedManagedPolicies", [])]
            self.graph.add_node(
                arn,
                id=arn,
                type="user",
                account_id=acc,
                name=u.get("UserName", arn.split("/")[-1]),
                attached_policies=attached,
                is_admin_equivalent=is_admin,
            )

        # 2. Add Roles
        for r in self.parser.roles:
            arn = r["Arn"]
            acc = extract_account_id(arn)
            self.accounts.add(acc)
            is_admin = self.parser.is_admin_equivalent(r)
            attached = [p["PolicyArn"] for p in r.get("AttachedManagedPolicies", [])]
            self.graph.add_node(
                arn,
                id=arn,
                type="role",
                account_id=acc,
                name=r.get("RoleName", arn.split("/")[-1]),
                attached_policies=attached,
                is_admin_equivalent=is_admin,
            )

        # 3. Add Groups
        for g in self.parser.groups:
            arn = g["Arn"]
            acc = extract_account_id(arn)
            self.accounts.add(acc)
            attached = [p["PolicyArn"] for p in g.get("AttachedManagedPolicies", [])]
            self.graph.add_node(
                arn,
                id=arn,
                type="group",
                account_id=acc,
                name=g.get("GroupName", arn.split("/")[-1]),
                attached_policies=attached,
                is_admin_equivalent=False,
            )

        # 4. Add Group Memberships
        for u in self.parser.users:
            u_arn = u["Arn"]
            u_acc = extract_account_id(u_arn)
            for grp_name in u.get("GroupList", []):
                # Resolve group ARN
                grp_arn = f"arn:aws:iam::{u_acc}:group/{grp_name}"
                if grp_arn in self.graph:
                    self.graph.add_edge(
                        u_arn,
                        grp_arn,
                        permission="group_membership",
                        condition=None,
                        is_wildcard_resource=False,
                    )

        # 5. Add Policy Attachment Edges
        for p in self.parser.managed_policies:
            p_arn = p["Arn"]
            p_acc = extract_account_id(p_arn)
            if p_acc != "aws":
                self.accounts.add(p_acc)
            self.graph.add_node(
                p_arn,
                id=p_arn,
                type="policy",
                account_id=p_acc,
                name=p.get("PolicyName", p_arn.split("/")[-1]),
                attached_policies=[],
                is_admin_equivalent=("AdministratorAccess" in p_arn),
            )

        for entity_list in [self.parser.users, self.parser.roles, self.parser.groups]:
            for entity in entity_list:
                src_arn = entity["Arn"]
                for att in entity.get("AttachedManagedPolicies", []):
                    pol_arn = att["PolicyArn"]
                    self.graph.add_edge(
                        src_arn,
                        pol_arn,
                        permission="policy_attachment",
                        condition=None,
                        is_wildcard_resource=False,
                    )

        # 6. Add AssumeRole Trust Edges
        # Inspect role trust policy documents
        for r in self.parser.roles:
            role_arn = r["Arn"]
            trust_doc = r.get("AssumeRolePolicyDocument", {})
            for stmt in trust_doc.get("Statement", []):
                if stmt.get("Effect", "") == "Allow" and stmt.get("Action") in ["sts:AssumeRole", ["sts:AssumeRole"]]:
                    principal = stmt.get("Principal", {})
                    cond = stmt.get("Condition")
                    trusted_aws = principal.get("AWS")
                    if trusted_aws:
                        trusted_list = [trusted_aws] if isinstance(trusted_aws, str) else list(trusted_aws)
                        for src_principal in trusted_list:
                            if src_principal in self.graph:
                                self.graph.add_edge(
                                    src_principal,
                                    role_arn,
                                    permission="sts:AssumeRole",
                                    condition=cond,
                                    is_wildcard_resource=False,
                                )

        # 7. Add Permission-Based Edges (sts:AssumeRole & iam:PassRole targets from policies)
        for entity_list in [self.parser.users, self.parser.roles]:
            for entity in entity_list:
                src_arn = entity["Arn"]
                stmts = self.parser.get_principal_statements(entity)
                for s in stmts:
                    if not s.is_allow():
                        continue

                    # AssumeRole permission in policy
                    if any("sts:AssumeRole" in a or a == "*" for a in s.actions):
                        for res in s.resources:
                            if res in self.graph and res != src_arn:
                                self.graph.add_edge(
                                    src_arn,
                                    res,
                                    permission="sts:AssumeRole",
                                    condition=s.condition,
                                    is_wildcard_resource=(res == "*"),
                                )

                    # PassRole permission in policy
                    if any("iam:PassRole" in a or a == "*" for a in s.actions):
                        for res in s.resources:
                            if res in self.graph and res != src_arn:
                                self.graph.add_edge(
                                    src_arn,
                                    res,
                                    permission="iam:PassRole",
                                    condition=s.condition,
                                    is_wildcard_resource=(res == "*"),
                                )
                            elif res == "*":
                                # Mark potential pass role to all roles
                                for r in self.parser.roles:
                                    if r["Arn"] != src_arn:
                                        self.graph.add_edge(
                                            src_arn,
                                            r["Arn"],
                                            permission="iam:PassRole",
                                            condition=s.condition,
                                            is_wildcard_resource=True,
                                        )

        return self.graph

    def export_dict(self) -> Dict[str, Any]:
        """Serializes the graph to the Section 2.1 JSON schema dictionary."""
        if len(self.graph.nodes) == 0:
            self.build_graph()

        nodes_out = []
        for n, data in self.graph.nodes(data=True):
            nodes_out.append({
                "id": data.get("id", n),
                "type": data.get("type", "resource"),
                "account_id": data.get("account_id", extract_account_id(n)),
                "name": data.get("name", n.split("/")[-1]),
                "attached_policies": data.get("attached_policies", []),
                "is_admin_equivalent": bool(data.get("is_admin_equivalent", False)),
            })

        edges_out = []
        for u, v, data in self.graph.edges(data=True):
            edges_out.append({
                "source": u,
                "target": v,
                "permission": data.get("permission", "policy_attachment"),
                "condition": data.get("condition"),
                "is_wildcard_resource": bool(data.get("is_wildcard_resource", False)),
            })

        # Ensure unique accounts, sorted
        accounts_list = sorted(list(self.accounts)) if self.accounts else ["111111111111"]

        return {
            "accounts": accounts_list,
            "nodes": nodes_out,
            "edges": edges_out,
        }


def parse_and_export(input_path: str, output_path: str) -> Dict[str, Any]:
    """Parses raw authorization JSON and writes graph_export.json."""
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    parser = IAMParser(data, source_name=input_path)
    builder = IAMGraphBuilder(parser)
    graph_dict = builder.export_dict()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(graph_dict, f, indent=2)

    return graph_dict


if __name__ == "__main__":
    import sys
    inp = sys.argv[1] if len(sys.argv) > 1 else "sample_data/iam_export_sample.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "graph_export.json"
    parse_and_export(inp, out)
    print(f"Graph exported to {out}")
