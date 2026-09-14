"""
parser.py — Person 1 (Parser & Graph Builder)
Loads a GetAccountAuthorizationDetails-style IAM JSON export and extracts
normalized entities: users, roles, groups, policies, and policy statements.
"""

import json
from typing import Any


# ---------------------------------------------------------------------------
# Data-loading
# ---------------------------------------------------------------------------

def load_iam_export(path: str) -> dict:
    """Load and return the raw IAM export JSON from the given file path."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Statement normalization
# ---------------------------------------------------------------------------

def _ensure_list(value: Any) -> list:
    """Wrap a scalar value in a list; leave lists unchanged."""
    if isinstance(value, list):
        return value
    return [value]


def normalize_statements(policy_doc: dict) -> list[dict]:
    """
    Convert a raw IAM policy document into a list of normalized statement tuples.

    Each returned dict has keys:
        sid        (str | None)
        effect     ("Allow" | "Deny")
        principal  (list[str] | None)   — None for resource-based if absent
        actions    (list[str])
        resources  (list[str])
        condition  (dict | None)
    """
    statements = []
    for stmt in policy_doc.get("Statement", []):
        principal_raw = stmt.get("Principal")
        if principal_raw is None:
            principals = None
        elif isinstance(principal_raw, str):
            principals = [principal_raw]
        elif isinstance(principal_raw, dict):
            # {"AWS": [...], "Service": [...], ...} — flatten to flat list
            principals = []
            for vals in principal_raw.values():
                principals.extend(_ensure_list(vals))
        else:
            principals = list(principal_raw)

        action_raw = stmt.get("Action", [])
        actions = _ensure_list(action_raw)

        resource_raw = stmt.get("Resource", [])
        resources = _ensure_list(resource_raw)

        statements.append({
            "sid": stmt.get("Sid"),
            "effect": stmt.get("Effect", "Allow"),
            "principal": principals,
            "actions": actions,
            "resources": resources,
            "condition": stmt.get("Condition"),
        })
    return statements


# ---------------------------------------------------------------------------
# Entity extractors
# ---------------------------------------------------------------------------

def extract_users(raw: dict) -> list[dict]:
    """Return a cleaned list of user records from the raw export."""
    users = []
    for u in raw.get("UserDetailList", []):
        users.append({
            "arn": u["Arn"],
            "user_id": u["UserId"],
            "name": u["UserName"],
            "account_id": _account_from_arn(u["Arn"]),
            "groups": u.get("GroupList", []),
            "attached_policies": [
                p["PolicyArn"] for p in u.get("AttachedManagedPolicies", [])
            ],
            "inline_policies": _parse_inline_policies(u.get("UserPolicyList", [])),
        })
    return users


def extract_roles(raw: dict) -> list[dict]:
    """Return a cleaned list of role records including their trust policy statements."""
    roles = []
    for r in raw.get("RoleDetailList", []):
        trust_doc = r.get("AssumeRolePolicyDocument", {})
        roles.append({
            "arn": r["Arn"],
            "role_id": r["RoleId"],
            "name": r["RoleName"],
            "account_id": _account_from_arn(r["Arn"]),
            "attached_policies": [
                p["PolicyArn"] for p in r.get("AttachedManagedPolicies", [])
            ],
            "inline_policies": _parse_inline_policies(r.get("RolePolicyList", [])),
            "trust_statements": normalize_statements(trust_doc),
        })
    return roles


def extract_groups(raw: dict) -> list[dict]:
    """Return a cleaned list of group records."""
    groups = []
    for g in raw.get("GroupDetailList", []):
        groups.append({
            "arn": g["Arn"],
            "group_id": g["GroupId"],
            "name": g["GroupName"],
            "account_id": _account_from_arn(g["Arn"]),
            "attached_policies": [
                p["PolicyArn"] for p in g.get("AttachedManagedPolicies", [])
            ],
            "inline_policies": _parse_inline_policies(g.get("GroupPolicyList", [])),
        })
    return groups


def extract_policies(raw: dict) -> dict[str, dict]:
    """
    Return a dict mapping policy ARN → policy record with normalized statements.
    Only the default active version's statements are retained.
    """
    policy_map = {}
    for p in raw.get("Policies", []):
        arn = p["Arn"]
        default_vid = p.get("DefaultVersionId", "v1")
        doc = {}
        for version in p.get("PolicyVersionList", []):
            if version.get("VersionId") == default_vid or version.get("IsDefaultVersion"):
                doc = version.get("Document", {})
                break
        policy_map[arn] = {
            "arn": arn,
            "name": p["PolicyName"],
            "account_id": _account_from_arn(arn),
            "statements": normalize_statements(doc),
        }
    return policy_map


# ---------------------------------------------------------------------------
# Admin-equivalence detection
# ---------------------------------------------------------------------------

def compute_is_admin_equivalent(
    principal_arns: list[str],
    users: list[dict],
    roles: list[dict],
    groups: list[dict],
    policy_map: dict[str, dict],
) -> dict[str, bool]:
    """
    Compute is_admin_equivalent for every principal ARN.

    A principal is admin-equivalent when ANY of the following is true:
    - It has AdministratorAccess (arn:aws:iam::aws:policy/AdministratorAccess) attached.
    - Its effective policy set contains a statement with Effect=Allow, Action=*, Resource=*.
    - It is in a group that satisfies either condition above.

    Returns a dict mapping arn → bool.
    """
    # Build group → policies index
    group_by_name: dict[str, dict] = {g["name"]: g for g in groups}
    result: dict[str, bool] = {}

    for arn in principal_arns:
        result[arn] = _check_admin(arn, users, roles, groups, group_by_name, policy_map)

    # Also compute for roles (roles can be principals in their own right)
    for role in roles:
        if role["arn"] not in result:
            result[role["arn"]] = _check_admin(
                role["arn"], users, roles, groups, group_by_name, policy_map
            )

    return result


def _check_admin(
    arn: str,
    users: list[dict],
    roles: list[dict],
    groups: list[dict],
    group_by_name: dict[str, dict],
    policy_map: dict[str, dict],
) -> bool:
    """Return True if the principal identified by arn has admin-equivalent access."""
    # Find the principal record
    principal = None
    for u in users:
        if u["arn"] == arn:
            principal = u
            break
    if principal is None:
        for r in roles:
            if r["arn"] == arn:
                principal = r
                break
    if principal is None:
        return False

    # Collect all policy ARNs this principal has (direct + via groups)
    policy_arns = list(principal.get("attached_policies", []))

    for group_name in principal.get("groups", []):
        grp = group_by_name.get(group_name)
        if grp:
            policy_arns.extend(grp.get("attached_policies", []))

    # Check for AdministratorAccess by ARN
    if "arn:aws:iam::aws:policy/AdministratorAccess" in policy_arns:
        return True

    # Check all attached + inline policies for Allow *:* on *
    all_statements: list[dict] = list(principal.get("inline_policies", []))
    for parn in policy_arns:
        pol = policy_map.get(parn)
        if pol:
            all_statements.extend(pol["statements"])

    for stmt in all_statements:
        if stmt["effect"] != "Allow":
            continue
        actions = stmt["actions"]
        resources = stmt["resources"]
        if ("*" in actions or "iam:*" in actions) and "*" in resources:
            return True

    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _account_from_arn(arn: str) -> str:
    """Extract the 12-digit account ID from a full ARN."""
    parts = arn.split(":")
    return parts[4] if len(parts) >= 5 else "unknown"


def _parse_inline_policies(policy_list: list[dict]) -> list[dict]:
    """Normalize a list of inline policy objects into statement tuples."""
    statements = []
    for pol in policy_list:
        doc = pol.get("PolicyDocument", {})
        statements.extend(normalize_statements(doc))
    return statements

