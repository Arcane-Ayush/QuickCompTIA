"""Unit tests verifying detection engine accuracy, contract compliance, and chain detection."""

import json
from pathlib import Path
import unittest
from detection_engine.detector import run_detection


class TestDetectionEngine(unittest.TestCase):
    """Test suite evaluating the Person 2 detection engine against Section 2.2 contract."""

    @classmethod
    def setUpClass(cls) -> None:
        """Set up test environment and resolve sample graph export path."""
        cls.test_dir = Path(__file__).parent
        cls.test_graph = cls.test_dir / "test_graph_export.json"
        cls.output_findings = cls.test_dir / "test_findings_output.json"

    def tearDown(self) -> None:
        """Clean up output files created during test execution."""
        if self.output_findings.exists():
            self.output_findings.unlink()

    def test_detection_runs_and_catches_all_chains(self) -> None:
        """Verify detector catches all 3 embedded escalation chains and multi-hop paths."""
        results = run_detection(str(self.test_graph), str(self.output_findings))
        findings = results.get("findings", [])
        self.assertGreaterEqual(len(findings), 4)

        # 1. Verify PassRole+RunInstances chain is caught
        passrole_findings = [
            f for f in findings
            if f["type"] == "known_pattern" and "PassRole" in f["pattern_name"]
        ]
        self.assertTrue(len(passrole_findings) > 0, "PassRole+RunInstances pattern was not caught")
        passrole_finding = passrole_findings[0]
        self.assertIn("arn:aws:iam::111111111111:user/dev-alice", passrole_finding["path"])
        self.assertIn("arn:aws:iam::111111111111:role/AdminRole", passrole_finding["path"])

        # 2. Verify CreatePolicyVersion chain is caught
        policy_ver_findings = [
            f for f in findings
            if f["type"] == "known_pattern" and "CreatePolicyVersion" in f["pattern_name"]
        ]
        self.assertTrue(len(policy_ver_findings) > 0, "CreatePolicyVersion pattern was not caught")
        self.assertIn("arn:aws:iam::111111111111:user/ops-bob", policy_ver_findings[0]["path"])

        # 3. Verify sts:AssumeRole cross-account/trust chain is caught
        assume_findings = [
            f for f in findings
            if "AssumeRole" in f["pattern_name"] or any("contractor-charlie" in p for p in f["path"])
        ]
        self.assertTrue(len(assume_findings) > 0, "sts:AssumeRole trust pivot was not caught")

        # 4. Verify novel multi-hop path (analyst-eve -> StagingRole -> ProdAdminRole) is caught
        novel_findings = [
            f for f in findings
            if f["type"] == "novel_path" and "analyst-eve" in str(f["path"])
        ]
        self.assertTrue(len(novel_findings) > 0, "Novel multi-hop escalation path was not caught")

        # 5. Verify wildcard over-permissions are caught
        wildcard_findings = [f for f in findings if f["type"] == "wildcard_overpermission"]
        self.assertTrue(len(wildcard_findings) > 0, "Wildcard over-permission was not caught")

    def test_findings_strict_schema_contract(self) -> None:
        """Validate findings against strict Section 2.2 JSON schema specifications."""
        results = run_detection(str(self.test_graph), str(self.output_findings))
        findings = results.get("findings", [])

        allowed_types = {"known_pattern", "novel_path", "wildcard_overpermission"}

        for f in findings:
            # Verify required keys
            self.assertIn("finding_id", f)
            self.assertIn("type", f)
            self.assertIn("pattern_name", f)
            self.assertIn("path", f)
            self.assertIn("risk_score", f)
            self.assertIn("risk_breakdown", f)
            self.assertIn("narrative", f)
            self.assertIn("offending_statement", f)

            # Check types & constraints
            self.assertTrue(f["finding_id"].startswith("F-"))
            self.assertIn(f["type"], allowed_types)
            self.assertIsInstance(f["pattern_name"], str)
            self.assertIsInstance(f["path"], list)
            self.assertIsInstance(f["risk_score"], (int, float))
            self.assertGreaterEqual(f["risk_score"], 0.0)
            self.assertLessEqual(f["risk_score"], 100.0)

            # Check risk_breakdown
            rb = f["risk_breakdown"]
            self.assertIn("reachability", rb)
            self.assertIn("blast_radius", rb)
            self.assertIn("exploit_triviality", rb)
            for factor_key in ("reachability", "blast_radius", "exploit_triviality"):
                self.assertIsInstance(rb[factor_key], (int, float))
                self.assertGreaterEqual(rb[factor_key], 0.0)
                self.assertLessEqual(rb[factor_key], 1.0)

            # Check narrative
            self.assertIsInstance(f["narrative"], str)
            self.assertGreater(len(f["narrative"]), 10)

            # Check offending_statement
            stmt = f["offending_statement"]
            self.assertIn("policy_arn", stmt)
            self.assertIn("action", stmt)
            self.assertIn("resource", stmt)
            self.assertIsInstance(stmt["policy_arn"], str)
            self.assertIsInstance(stmt["action"], str)
            self.assertIsInstance(stmt["resource"], str)


if __name__ == "__main__":
    unittest.main()
