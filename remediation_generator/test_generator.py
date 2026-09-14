"""Unit tests for RemediationGenerator module."""

import os
import json
import unittest
from remediation_generator.generator import RemediationGenerator
from remediation_generator.remediation_rules import extract_account_id


class TestRemediationGenerator(unittest.TestCase):
    """Test suite verifying RemediationGenerator compliance and logic."""

    def setUp(self) -> None:
        """Set up test environment and load sample findings dataset."""
        self.sample_findings_path = os.path.join(
            os.path.dirname(__file__), "sample_findings.json"
        )
        with open(self.sample_findings_path, "r", encoding="utf-8") as f:
            self.findings_data = json.load(f)
        self.generator = RemediationGenerator()

    def test_account_id_extraction(self) -> None:
        """Test account ID extraction from AWS IAM ARNs."""
        arn = "arn:aws:iam::222222222222:policy/TestPolicy"
        self.assertEqual(extract_account_id(arn), "222222222222")
        self.assertEqual(extract_account_id(None), "111111111111")

    def test_remediation_generation_schema(self) -> None:
        """Verify generated remediations output structure matches Section 2.3 schema."""
        result = self.generator.generate_remediations(self.findings_data)
        self.assertIn("remediations", result)
        remediations = result["remediations"]
        self.assertEqual(len(remediations), len(self.findings_data["findings"]))

        for item in remediations:
            self.assertIn("finding_id", item)
            self.assertIn("justification", item)
            self.assertTrue(isinstance(item["justification"], str))
            self.assertTrue(len(item["justification"]) > 0)

            if item.get("remediable") is False:
                self.assertIn("reason", item)
            else:
                self.assertIn("original_statement", item)
                self.assertIn("suggested_statement", item)
                suggested = item["suggested_statement"]
                self.assertIn("action", suggested)
                self.assertIn("resource", suggested)

    def test_passrole_remediation(self) -> None:
        """Verify PassRole over-permission is remediated with condition and role scope."""
        passrole_finding = self.findings_data["findings"][0]
        remediation = self.generator.generate_remediation_for_finding(passrole_finding)

        self.assertEqual(remediation["finding_id"], "F-001")
        suggested = remediation["suggested_statement"]
        self.assertEqual(suggested["action"], "iam:PassRole")
        self.assertIn("condition", suggested)
        self.assertIn("iam:PassedToService", suggested["condition"]["StringEquals"])
        self.assertEqual(suggested["condition"]["StringEquals"]["iam:PassedToService"], "ec2.amazonaws.com")
        self.assertIn("Restricts PassRole", remediation["justification"])

    def test_wildcard_s3_remediation(self) -> None:
        """Verify s3:* wildcard permission is replaced with explicit S3 actions."""
        s3_finding = self.findings_data["findings"][2]
        remediation = self.generator.generate_remediation_for_finding(s3_finding)

        suggested = remediation["suggested_statement"]
        self.assertIsInstance(suggested["action"], list)
        self.assertIn("s3:GetObject", suggested["action"])
        self.assertNotEqual(suggested["resource"], "*")

    def test_usage_data_trimming(self) -> None:
        """Test stretch feature for CloudTrail usage data-grounded action trimming."""
        mock_usage = {
            "arn:aws:iam::111111111111:policy/AnalyticsS3Policy": ["s3:GetObject"]
        }
        usage_generator = RemediationGenerator(usage_data=mock_usage)
        s3_finding = self.findings_data["findings"][2]
        remediation = usage_generator.generate_remediation_for_finding(s3_finding)

        suggested = remediation["suggested_statement"]
        self.assertEqual(suggested["action"], ["s3:GetObject"])
        self.assertIn("Usage-Grounded", remediation["justification"])


if __name__ == "__main__":
    unittest.main()
