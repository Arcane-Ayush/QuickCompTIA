"""Integration test suite for the full IAM Misconfiguration Detector pipeline."""

import os
import json
import unittest
from main import run_pipeline


class TestFullPipelineIntegration(unittest.TestCase):
    """Integration test validating pipeline execution and schema compliance."""

    def test_pipeline_execution(self) -> None:
        """Run full pipeline and verify all contract JSON files generated and valid."""
        run_pipeline(input_iam_path="sample_data/iam_export_sample.json", out_dir=".")
        
        self.assertTrue(os.path.exists("graph_export.json"))
        self.assertTrue(os.path.exists("findings.json"))
        self.assertTrue(os.path.exists("remediations.json"))

        with open("graph_export.json", "r") as f:
            graph = json.load(f)
            self.assertIn("nodes", graph)
            self.assertIn("edges", graph)

        with open("findings.json", "r") as f:
            findings = json.load(f)
            self.assertIn("findings", findings)

        with open("remediations.json", "r") as f:
            remediations = json.load(f)
            self.assertIn("remediations", remediations)


if __name__ == "__main__":
    unittest.main()
