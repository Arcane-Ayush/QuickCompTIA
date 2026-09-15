"""
Parser Module — IAM Authorization Document Parser & Statement Normalizer
Person 1 Module — /parser_graph/parser.py
"""

from typing import Any, Dict, List, Optional, Tuple


class NormalizedStatement:
    """Represents a normalized IAM policy statement tuple: (Effect, Principal, Actions, Resources, Condition)."""

    def __init__(
        self,
        effect: str,
        principal: Optional[Any],
        actions: List[str],
        resources: List[str],
        condition: Optional[Dict[str, Any]],
        source_policy_arn: str,
    ):
        """Initializes a normalized statement."""
        self.effect = effect
        self.principal = principal
        self.actions = actions
        self.resources = resources
        self.condition = condition
        self.source_policy_arn = source_policy_arn

    def is_allow(self) -> bool:
        """Returns True if statement effect is Allow."""
        return self.effect.lower() == "allow"

    def has_admin_privileges(self) -> bool:
        """Returns True if the statement grants unrestricted admin access."""
        if not self.is_allow():
            return False
        has_wildcard_action = "*" in self.actions or "*:*" in self.actions
        has_wildcard_resource = "*" in self.resources or len(self.resources) == 0
        return has_wildcard_action and has_wildcard_resource


def normalize_string_or_list(val: Any) -> List[str]:
    """Ensures a string or list is normalized to a list of strings."""
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(x) for x in val]
    return [str(val)]


def extract_statements_from_doc(doc: Dict[str, Any], policy_arn: str) -> List[NormalizedStatement]:
    """Extracts and normalizes all statements from an IAM policy document."""
    stmts: List[NormalizedStatement] = []
    raw_stmts = doc.get("Statement", [])
    if isinstance(raw_stmts, dict):
        raw_stmts = [raw_stmts]

    for stmt in raw_stmts:
        effect = stmt.get("Effect", "Deny")
        principal = stmt.get("Principal")
        actions = normalize_string_or_list(stmt.get("Action", []))
        resources = normalize_string_or_list(stmt.get("Resource", []))
        condition = stmt.get("Condition")
        stmts.append(
            NormalizedStatement(
                effect=effect,
                principal=principal,
                actions=actions,
                resources=resources,
                condition=condition,
                source_policy_arn=policy_arn,
            )
        )
    return stmts


class IAMParser:
    """Parses AWS GetAccountAuthorizationDetails export into principals, policies, and statements."""

    def __init__(self, raw_data: Dict[str, Any]):
        """Initializes parser with raw authorization details dict or standalone IAM policy document."""
        self.raw_data = raw_data or {}
        
        # Standalone IAM Policy Document auto-wrapping
        if "Statement" in self.raw_data or "Version" in self.raw_data:
            synthetic_policy_arn = "arn:aws:iam::111111111111:policy/CustomPolicy"
            self.managed_policies = [
                {
                    "Arn": synthetic_policy_arn,
                    "PolicyName": "CustomPolicy",
                    "PolicyId": "ANPA111111111111CUSTOM",
                    "Path": "/",
                    "DefaultVersionId": "v1",
                    "AttachmentCount": 1,
                    "IsAttachable": True,
                    "PolicyVersionList": [
                        {
                            "Document": self.raw_data,
                            "VersionId": "v1",
                            "IsDefaultVersion": True
                        }
                    ]
                }
            ]
            self.users = [
                {
                    "Arn": "arn:aws:iam::111111111111:user/custom-policy-user",
                    "UserName": "custom-policy-user",
                    "UserId": "AIDA111111111111CUSTOM",
                    "Path": "/",
                    "AttachedManagedPolicies": [
                        {"PolicyArn": synthetic_policy_arn, "PolicyName": "CustomPolicy"}
                    ]
                }
            ]
            self.roles = []
            self.groups = []
        elif "UserName" in self.raw_data and "UserDetailList" not in self.raw_data:
            self.users = [self.raw_data]
            self.roles = []
            self.groups = []
            self.managed_policies = []
        elif "RoleName" in self.raw_data and "RoleDetailList" not in self.raw_data:
            self.users = []
            self.roles = [self.raw_data]
            self.groups = []
            self.managed_policies = []
        else:
            self.users = self.raw_data.get("UserDetailList", [])
            self.roles = self.raw_data.get("RoleDetailList", [])
            self.groups = self.raw_data.get("GroupDetailList", [])
            self.managed_policies = self.raw_data.get("Policies", [])

        self.policy_doc_lookup: Dict[str, Dict[str, Any]] = {}
        self._index_managed_policies()

    def _index_managed_policies(self) -> None:
        """Indexes default document for each managed policy."""
        for pol in self.managed_policies:
            arn = pol.get("Arn")
            for ver in pol.get("PolicyVersionList", []):
                if ver.get("IsDefaultVersion", False):
                    self.policy_doc_lookup[arn] = ver.get("Document", {})
                    break

    def get_principal_statements(self, principal: Dict[str, Any]) -> List[NormalizedStatement]:
        """Gathers all normalized statements across inline and attached policies for a principal."""
        statements: List[NormalizedStatement] = []

        # 1. Attached managed policies
        for att in principal.get("AttachedManagedPolicies", []):
            arn = att.get("PolicyArn")
            if arn in self.policy_doc_lookup:
                statements.extend(extract_statements_from_doc(self.policy_doc_lookup[arn], arn))

        # 2. Inline policies for user/role/group
        inline_list = principal.get("UserPolicyList") or principal.get("RolePolicyList") or principal.get("GroupPolicyList") or []
        for inline in inline_list:
            inline_name = inline.get("PolicyName", "inline")
            arn = f"{principal.get('Arn')}:inline/{inline_name}"
            doc = inline.get("PolicyDocument", {})
            statements.extend(extract_statements_from_doc(doc, arn))

        return statements

    def is_admin_equivalent(self, principal: Dict[str, Any]) -> bool:
        """Computes whether a principal has effective administrator equivalency."""
        # Direct check for AdministratorAccess attachment
        for att in principal.get("AttachedManagedPolicies", []):
            if "AdministratorAccess" in att.get("PolicyArn", ""):
                return True

        # Check statement permissions
        for stmt in self.get_principal_statements(principal):
            if stmt.has_admin_privileges():
                return True

        return False
