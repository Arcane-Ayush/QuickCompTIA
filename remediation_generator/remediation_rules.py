"""Rule-based engine for IAM remediation generation."""

import re
from typing import Dict, Any, Optional, Tuple


def extract_account_id(arn: Optional[str]) -> str:
    """Extract AWS account ID from an ARN or return default account ID."""
    if arn and isinstance(arn, str):
        match = re.search(r"arn:aws:iam::(\d{12}):", arn)
        if match:
            return match.group(1)
    return "111111111111"


def get_rule_for_pattern(pattern_name: str, offending_statement: Dict[str, Any], path: Optional[list] = None) -> Tuple[Dict[str, Any], str]:
    """Select appropriate remediation rule template based on attack pattern name and offending statement."""
    pattern_lower = (pattern_name or "").lower()
    action = offending_statement.get("action")
    action_str = action[0] if isinstance(action, list) and action else str(action or "")
    policy_arn = offending_statement.get("policy_arn", "")
    account_id = extract_account_id(policy_arn)
    
    if path and len(path) > 1:
        target_arn = path[-1]
        target_account = extract_account_id(target_arn)
        if target_account != "111111111111":
            account_id = target_account

    if "passrole" in pattern_lower or "passrole" in action_str.lower():
        return generate_passrole_remediation(account_id, path)
    elif "policyversion" in pattern_lower or "createpolicyversion" in action_str.lower():
        return generate_policyversion_remediation(account_id)
    elif "attach" in pattern_lower or "put" in pattern_lower or any(act in action_str.lower() for act in ["attachuserpolicy", "attachrolepolicy", "putuserpolicy", "putrolepolicy"]):
        return generate_policy_attachment_remediation(account_id)
    elif "accesskey" in pattern_lower or "loginprofile" in pattern_lower or any(act in action_str.lower() for act in ["createaccesskey", "createloginprofile", "updateloginprofile"]):
        return generate_credential_creation_remediation(account_id)
    elif "assumerole" in pattern_lower or "assumerole" in action_str.lower():
        return generate_assumerole_remediation(account_id, path)
    else:
        return generate_generic_wildcard_remediation(action_str, offending_statement.get("resource", "*"), account_id)


def generate_passrole_remediation(account_id: str, path: Optional[list] = None) -> Tuple[Dict[str, Any], str]:
    """Generate minimal-privilege replacement statement for iam:PassRole over-permission."""
    target_role_arn = f"arn:aws:iam::{account_id}:role/AppRole-*"
    if path and len(path) > 1 and "role/" in path[-1]:
        target_role_arn = path[-1]

    suggested = {
        "action": "iam:PassRole",
        "resource": target_role_arn,
        "condition": {
            "StringEquals": {
                "iam:PassedToService": "ec2.amazonaws.com"
            }
        }
    }
    justification = "Restricts PassRole to only the designated application role and enforces ec2.amazonaws.com target service, preventing arbitrary administrative role privilege escalation."
    return suggested, justification


def generate_policyversion_remediation(account_id: str) -> Tuple[Dict[str, Any], str]:
    """Generate minimal-privilege replacement statement for iam:CreatePolicyVersion self-privesc."""
    suggested = {
        "action": "iam:CreatePolicyVersion",
        "resource": f"arn:aws:iam::{account_id}:policy/scoped-app-*",
        "condition": {
            "StringEquals": {
                "aws:PrincipalTag/Environment": "Dev"
            }
        }
    }
    justification = "Scopes policy version creation to application managed policy ARNs and requires environment tagging match, preventing administrative policy modification."
    return suggested, justification


def generate_policy_attachment_remediation(account_id: str) -> Tuple[Dict[str, Any], str]:
    """Generate minimal-privilege replacement statement for policy attachment actions."""
    suggested = {
        "action": "iam:AttachRolePolicy",
        "resource": f"arn:aws:iam::{account_id}:role/ScopedAppRole-*",
        "condition": {
            "ArnEquals": {
                "iam:PolicyARN": f"arn:aws:iam::{account_id}:policy/AppPermissionsPolicy"
            }
        }
    }
    justification = "Limits policy attachment to designated role ARNs and enforces exact match on approved policy ARNs."
    return suggested, justification


def generate_credential_creation_remediation(account_id: str) -> Tuple[Dict[str, Any], str]:
    """Generate minimal-privilege replacement statement for user credential creation actions."""
    suggested = {
        "action": [
            "iam:CreateAccessKey",
            "iam:DeleteAccessKey",
            "iam:ListAccessKeys"
        ],
        "resource": f"arn:aws:iam::{account_id}:user/${{aws:username}}",
        "condition": None
    }
    justification = "Restricts credential management actions strictly to the user's own IAM identity via ${aws:username} policy variable."
    return suggested, justification


def generate_assumerole_remediation(account_id: str, path: Optional[list] = None) -> Tuple[Dict[str, Any], str]:
    """Generate minimal-privilege replacement statement for sts:AssumeRole privilege escalation."""
    target_role = f"arn:aws:iam::{account_id}:role/WorkloadRole-*"
    if path and len(path) > 1 and "role/" in path[-1]:
        target_role = path[-1]

    suggested = {
        "action": "sts:AssumeRole",
        "resource": target_role,
        "condition": {
            "StringEquals": {
                "sts:ExternalId": "EnforceExternalIdCheck"
            }
        }
    }
    justification = "Narrows AssumeRole target to explicit workload role ARNs and requires ExternalId verification to block unauthorized lateral movement."
    return suggested, justification


def generate_generic_wildcard_remediation(action_str: str, resource_val: Any, account_id: str) -> Tuple[Dict[str, Any], str]:
    """Generate minimal-privilege replacement statement for generic wildcard action/resource over-permissions."""
    if action_str == "*" or action_str.lower() == "*:*":
        suggested_action = ["s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"]
        justification = "Replaces global full administrator wildcard (*:*) with specific, scoped read/write operations required by the service."
    elif ":" in action_str:
        service = action_str.split(":")[0].lower()
        if service == "s3":
            suggested_action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        elif service == "iam":
            suggested_action = ["iam:Get*", "iam:List*"]
        elif service == "ec2":
            suggested_action = ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"]
        elif service == "dynamodb":
            suggested_action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
        else:
            suggested_action = [f"{service}:Get*", f"{service}:List*"]
        justification = f"Replaces wildcard {service}:* grant with specific read/write operations for {service} service."
    else:
        suggested_action = action_str if action_str else "sts:GetCallerIdentity"
        justification = "Narrows wildcard permissions to specific non-administrative IAM actions."

    if resource_val == "*" or resource_val == ["*"]:
        service_prefix = action_str.split(":")[0].lower() if ":" in action_str else "app"
        if service_prefix == "s3":
            suggested_resource = f"arn:aws:s3:::app-data-{account_id}/*"
        elif service_prefix == "iam":
            suggested_resource = f"arn:aws:iam::{account_id}:role/AppRole-*"
        else:
            suggested_resource = f"arn:aws:{service_prefix}:{account_id}:resource/*"
    else:
        suggested_resource = resource_val

    suggested = {
        "action": suggested_action,
        "resource": suggested_resource,
        "condition": None
    }
    return suggested, justification
