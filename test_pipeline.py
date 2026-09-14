"""End-to-End Integration Test Suite for the full 4-module pipeline."""

import os
import json
import unittest
from app import run_stage_1_parser, run_stage_2_detector, run_stage_3_remediator


class TestFullPipelineIntegration(unittest.TestCase):
    """Integration test suite validating end-to-end execution and schema compliance."""

    def setUp(self) -> None:
        """Set up test environment file paths."""
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        self.sample_input = os.path.join(self.root_dir, "sample_data", "iam_export_sample.json")
        self.graph_out = os.path.join(self.root_dir, "test_graph_export.json")
        self.findings_out = os.path.join(self.root_dir, "test_findings.json")
        self.remediations_out = os.path.join(self.root_dir, "test_remediations.json")

    def tearDown(self) -> None:
        """Clean up temporary test output files."""
        for path in [self.graph_out, self.findings_out, self.remediations_out]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

    def test_full_pipeline_execution(self) -> None:
        """Test full pipeline execution from IAM sample export to remediations."""
        # Stage 1: Parser
        run_stage_1_parser(self.sample_input, self.graph_out)
        self.assertTrue(os.path.exists(self.graph_out))
        with open(self.graph_out, "r", encoding="utf-8") as f:
            graph = json.load(f)
        self.assertIn("accounts", graph)
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertTrue(len(graph["nodes"]) > 0)

        # Stage 2: Detector
        detector_results = run_stage_2_detector(self.graph_out, self.findings_out)
        self.assertTrue(os.path.exists(self.findings_out))
        self.assertIn("findings", detector_results)
        findings = detector_results["findings"]
        self.assertTrue(len(findings) > 0)

        # Verify findings structure (Section 2.2 schema)
        for finding in findings:
            self.assertIn("finding_id", finding)
            self.assertIn("type", finding)
            self.assertIn("risk_score", finding)
            self.assertIn("risk_breakdown", finding)
            self.assertIn("narrative", finding)

        # Stage 3: Remediation Generator
        remediations_results = run_stage_3_remediator(self.findings_out, self.remediations_out)
        self.assertTrue(os.path.exists(self.remediations_out))
        self.assertIn("remediations", remediations_results)
        remediations = remediations_results["remediations"]
        self.assertEqual(len(remediations), len(findings))

        # Verify remediations structure (Section 2.3 schema)
        for rem in remediations:
            self.assertIn("finding_id", rem)
            self.assertIn("justification", rem)


if __name__ == "__main__":
    unittest.main()
