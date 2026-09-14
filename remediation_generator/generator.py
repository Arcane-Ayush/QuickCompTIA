"""Remediation Generator class for processing IAM findings and producing policy fixes."""

import json
from typing import Dict, Any, List, Optional
from .remediation_rules import get_rule_for_pattern


class RemediationGenerator:
    """Generates least-privilege policy replacement statements for cloud IAM findings."""

    def __init__(self, usage_data: Optional[Dict[str, Any]] = None) -> None:
        """Initialize generator with optional CloudTrail/last-used activity dataset."""
        self.usage_data = usage_data or {}

    def generate_remediation_for_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a single remediation record for a given finding dictionary."""
        finding_id = finding.get("finding_id", "F-000")
        finding_type = finding.get("type", "wildcard_overpermission")
        pattern_name = finding.get("pattern_name", "")
        path = finding.get("path", [])
        offending_statement = finding.get("offending_statement", {})

        # Normalize original statement for schema output
        original_statement = self._format_original_statement(offending_statement)

        # Handle non-remediable novel paths without clear offending statements
        if finding_type == "novel_path" and not offending_statement:
            return {
                "finding_id": finding_id,
                "remediable": False,
                "reason": "Novel path finding requires manual architectural review of trust graph.",
                "original_statement": original_statement,
                "justification": "Manual architectural review required due to indirect trust relationship escalation path."
            }

        # Apply rule engine to derive suggested replacement statement
        suggested_statement, justification = get_rule_for_pattern(pattern_name, offending_statement, path)

        # Apply CloudTrail usage trimming if usage data exists (Stretch Feature)
        if self.usage_data and "policy_arn" in offending_statement:
            suggested_statement, usage_note = self.trim_with_usage_data(
                offending_statement.get("policy_arn"),
                suggested_statement
            )
            if usage_note:
                justification += f" {usage_note}"

        remediation_entry = {
            "finding_id": finding_id,
            "original_statement": original_statement,
            "suggested_statement": suggested_statement,
            "justification": justification
        }
        return remediation_entry

    def generate_remediations(self, findings_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Process findings data dictionary and return complete remediations payload matching Section 2.3 schema."""
        findings = findings_data.get("findings", [])
        remediations = []
        for finding in findings:
            remediation = self.generate_remediation_for_finding(finding)
            remediations.append(remediation)
        return {"remediations": remediations}

    def trim_with_usage_data(self, policy_arn: Optional[str], suggested_statement: Dict[str, Any]) -> tuple:
        """Trim unused actions from suggested statement based on CloudTrail usage activity."""
        if not policy_arn or policy_arn not in self.usage_data:
            return suggested_statement, ""

        used_actions = set(self.usage_data.get(policy_arn, []))
        action = suggested_statement.get("action")

        if isinstance(action, list):
            trimmed_actions = [act for act in action if act in used_actions]
            if trimmed_actions:
                suggested_statement["action"] = trimmed_actions
                return suggested_statement, f"[Usage-Grounded: Trimmed {len(action) - len(trimmed_actions)} unused actions based on CloudTrail log activity.]"
        elif isinstance(action, str) and action not in used_actions and used_actions:
            return suggested_statement, "[Usage-Grounded: Verified action against CloudTrail usage records.]"

        return suggested_statement, ""

    def _format_original_statement(self, offending_statement: Dict[str, Any]) -> Dict[str, Any]:
        """Format and extract action and resource fields from offending statement for output schema consistency."""
        if not offending_statement:
            return {"action": "*", "resource": "*"}

        action = offending_statement.get("action", "*")
        resource = offending_statement.get("resource", "*")

        formatted = {
            "action": action,
            "resource": resource
        }
        if "condition" in offending_statement and offending_statement["condition"]:
            formatted["condition"] = offending_statement["condition"]

        return formatted
