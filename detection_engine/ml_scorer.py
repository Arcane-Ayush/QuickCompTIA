"""
ML Scorer Module — Model Inference & 3-Factor Explainable Risk Scoring
Person 2 Module — /detection_engine/ml_scorer.py
"""

import os
import joblib
import numpy as np
from typing import Any, Dict, List, Optional, Tuple


class IAMRiskScorer:
    """Uses the trained machine learning model to evaluate IAM risk, exploit triviality, and composite risk."""

    def __init__(self, model_path: str = "detection_engine/models/iam_risk_classifier.pkl"):
        """Initializes scorer and loads model if present."""
        self.model = None
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
            except Exception as e:
                print(f"Warning: Failed to load ML model from {model_path}: {e}")

    def extract_features(
        self,
        principal_arn: str,
        path: List[str],
        shortest_path_dist: int,
        downstream_nodes: int,
        actions_present: List[str],
        resources_present: List[str],
        has_conditions: bool,
        is_cross_account: bool,
        in_degree: int = 1,
        out_degree: int = 1,
    ) -> np.ndarray:
        """Extracts the 12-dimensional feature vector for a principal and attack vector."""
        has_wildcard_action = 1.0 if any(a in ["*", "*:*"] for a in actions_present) else 0.0
        has_wildcard_resource = 1.0 if any(r == "*" for r in resources_present) else 0.0
        passrole_count = sum(1 for a in actions_present if "iam:PassRole" in a)
        create_policy_ver = sum(1 for a in actions_present if "iam:CreatePolicyVersion" in a)
        assume_role = sum(1 for a in actions_present if "sts:AssumeRole" in a)
        run_instances = sum(1 for a in actions_present if "ec2:RunInstances" in a)
        cross_acc = 1.0 if is_cross_account else 0.0
        cond = 1.0 if has_conditions else 0.0

        vec = [
            has_wildcard_action,
            has_wildcard_resource,
            float(passrole_count),
            float(create_policy_ver),
            float(assume_role),
            float(run_instances),
            cross_acc,
            float(shortest_path_dist),
            float(downstream_nodes),
            float(in_degree),
            float(out_degree),
            cond,
        ]
        return np.array([vec], dtype=np.float32)

    def score_vector(
        self,
        features: np.ndarray,
        base_exploit_triviality: float = 0.8,
        base_reachability: float = 0.9,
        base_blast_radius: float = 0.85,
    ) -> Tuple[float, Dict[str, float]]:
        """
        Computes composite Risk = Reachability * Blast_radius * Exploit_triviality (scaled 0-100)
        and returns the explainable 3-factor breakdown.
        """
        ml_prob = 0.85
        if self.model is not None:
            try:
                # Predict probability of privilege escalation class (1)
                probs = self.model.predict_proba(features)
                ml_prob = float(probs[0][1]) if len(probs[0]) > 1 else float(probs[0][0])
            except Exception:
                ml_prob = 0.85

        # Refine exploit triviality using model probability
        exploit_triviality = round(float(np.clip(base_exploit_triviality * 0.4 + ml_prob * 0.6, 0.1, 1.0)), 2)
        reachability = round(float(np.clip(base_reachability, 0.1, 1.0)), 2)
        blast_radius = round(float(np.clip(base_blast_radius, 0.1, 1.0)), 2)

        # Formula from Protocol Section 2.2: Risk = Reachability * Blast_radius * Exploit_triviality * 100
        composite_score = round(reachability * blast_radius * exploit_triviality * 100.0, 1)

        breakdown = {
            "reachability": reachability,
            "blast_radius": blast_radius,
            "exploit_triviality": exploit_triviality,
        }
        return composite_score, breakdown
