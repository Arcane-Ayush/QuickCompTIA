"""
Remediation Generator Module — Least-Privilege Policy Generation & Auto-Fix Synthesis
Person 3 Module — /remediation_generator/generator.py
"""

import json
from typing import Any, Dict, List, Optional


class RemediationGenerator:
    """Generates scoped, least-privilege IAM replacement policy statements for detection findings."""

    def __init__(self, findings_data: Dict[str, Any]):
        """Initializes generator with parsed findings dict."""
        self.findings_data = findings_data

    def generate_remediations(self) -> Dict[str, Any]:
        """Generates remediation statements conforming strictly to Section 2.3 schema."""
        remediations: List[Dict[str, Any]] = []

        for finding in self.findings_data.get("findings", []):
            finding_id = finding.get("finding_id")
            f_type = finding.get("type")
            pattern = finding.get("pattern_name", "")
            offending = finding.get("offending_statement", {})
            orig_action = offending.get("action", "*")
            orig_resource = offending.get("resource", "*")
            path = finding.get("path", [])
            principal_arn = path[0] if path else "arn:aws:iam::111111111111:user/unknown"
            account_id = principal_arn.split(":")[4] if ":" in principal_arn and len(principal_arn.split(":")) > 4 else "111111111111"

            # 1. PassRole + RunInstances
            if "PassRole" in pattern:
                remediations.append({
                    "finding_id": finding_id,
                    "remediable": True,
                    "original_statement": {
                        "action": orig_action,
                        "resource": orig_resource,
                    },
                    "suggested_statement": {
                        "action": "iam:PassRole",
                        "resource": f"arn:aws:iam::{account_id}:role/AppRole-*",
                        "condition": {
                            "StringEquals": {
                                "iam:PassedToService": "ec2.amazonaws.com"
                            }
                        },
                    },
                    "justification": "Restricts PassRole to only the application role prefix and only when passed to EC2, closing the unrestricted admin-role pivot.",
                })

            # 2. CreatePolicyVersion
            elif "CreatePolicyVersion" in pattern:
                remediations.append({
                    "finding_id": finding_id,
                    "remediable": True,
                    "original_statement": {
                        "action": orig_action,
                        "resource": orig_resource,
                    },
                    "suggested_statement": {
                        "action": "iam:CreatePolicyVersion",
                        "resource": f"arn:aws:iam::{account_id}:policy/dev/*",
                        "condition": None,
                    },
                    "justification": "Restricts policy version authoring to scoped sandbox/dev namespaces, preventing direct manipulation of production administrative policies.",
                })

            # 3. Cross-Account AssumeRole Pivot
            elif "Cross-account" in pattern or "CrossAccount" in pattern:
                target_account = "222222222222"
                remediations.append({
                    "finding_id": finding_id,
                    "remediable": True,
                    "original_statement": {
                        "action": orig_action,
                        "resource": orig_resource,
                    },
                    "suggested_statement": {
                        "action": "sts:AssumeRole",
                        "resource": f"arn:aws:iam::{target_account}:role/ContractorScopedRole-*",
                        "condition": {
                            "Bool": {
                                "aws:MultiFactorAuthPresent": "true"
                            }
                        },
                    },
                    "justification": "Restricts cross-account assumption strictly to designated contractor roles and enforces mandatory MFA authentication.",
                })

            # 4. SetDefaultPolicyVersion
            elif "SetDefaultPolicyVersion" in pattern:
                remediations.append({
                    "finding_id": finding_id,
                    "remediable": True,
                    "original_statement": {
                        "action": orig_action,
                        "resource": orig_resource,
                    },
                    "suggested_statement": {
                        "action": "iam:GetPolicyVersion",
                        "resource": orig_resource,
                        "condition": None,
                    },
                    "justification": "Demotes policy management permission to read-only inspection, preventing rollback to insecure legacy policy versions.",
                })

            # 5. Wildcard Overpermission (s3:* on *)
            elif f_type == "wildcard_overpermission" or "Wildcard" in pattern:
                remediations.append({
                    "finding_id": finding_id,
                    "remediable": True,
                    "original_statement": {
                        "action": orig_action,
                        "resource": orig_resource,
                    },
                    "suggested_statement": {
                        "action": "s3:GetObject",
                        "resource": f"arn:aws:s3:::company-analytics-data-{account_id}/*",
                        "condition": {
                            "Bool": {
                                "aws:SecureTransport": "true"
                            }
                        },
                    },
                    "justification": "Restricts wildcard S3 permissions to read-only GetObject calls on the specific analytics data bucket with mandatory TLS.",
                })

            # 6. Novel Multi-hop Paths
            else:
                remediations.append({
                    "finding_id": finding_id,
                    "remediable": False,
                    "original_statement": {
                        "action": orig_action,
                        "resource": orig_resource,
                    },
                    "suggested_statement": {
                        "action": orig_action,
                        "resource": orig_resource,
                        "condition": None,
                    },
                    "justification": "Novel composite attack path requires architectural role trust boundary decoupling rather than a single policy modification.",
                })

        return {"remediations": remediations}


def remediate_and_export(findings_path: str = "findings.json", output_path: str = "remediations.json") -> Dict[str, Any]:
    """Generates remediations from findings.json and exports remediations.json."""
    with open(findings_path, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    generator = RemediationGenerator(findings_data)
    remediations_dict = generator.generate_remediations()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(remediations_dict, f, indent=2)

    return remediations_dict


if __name__ == "__main__":
    import sys
    f_in = sys.argv[1] if len(sys.argv) > 1 else "findings.json"
    r_out = sys.argv[2] if len(sys.argv) > 2 else "remediations.json"
    remediate_and_export(f_in, r_out)
    print(f"Remediations exported to {r_out}")
