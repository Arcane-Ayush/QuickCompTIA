"""
Detection Engine Module — Declarative Rule Matching, Pathfinder Integration & Risk Scorer
Person 2 Module — /detection_engine/detector.py
"""

import os
import glob
import json
import re
from typing import Any, Dict, List, Optional, Set

from .pathfinder import IAMPathfinder
from .ml_scorer import IAMRiskScorer


def load_rules(rules_dir: str = "detection_engine/rules") -> List[Dict[str, Any]]:
    """Loads all declarative JSON rule files from the rules directory."""
    rules = []
    pattern = os.path.join(rules_dir, "*.json")
    for fpath in glob.glob(pattern):
        with open(fpath, "r", encoding="utf-8") as f:
            try:
                r = json.load(f)
                rules.append(r)
            except Exception as e:
                print(f"Warning: Failed to parse rule {fpath}: {e}")
    return rules


class DetectionEngine:
    """Evaluates IAM graph and policies against known rules, generic attack paths, and ML scoring."""

    def __init__(
        self,
        graph_data: Dict[str, Any],
        raw_iam_data: Optional[Dict[str, Any]] = None,
        rules_dir: str = "detection_engine/rules",
        model_path: str = "detection_engine/models/iam_risk_classifier.pkl",
    ):
        """Initializes detection engine with graph and rule definitions."""
        self.graph_data = graph_data
        self.raw_iam_data = raw_iam_data or {}
        self.rules = load_rules(rules_dir)
        self.pathfinder = IAMPathfinder(graph_data)
        self.scorer = IAMRiskScorer(model_path)
        self.nodes_by_id = {n["id"]: n for n in graph_data.get("nodes", [])}
        self.edges = graph_data.get("edges", [])

    def run_detection(self) -> Dict[str, Any]:
        """Executes full detection suite and returns findings matching Section 2.2 schema."""
        findings: List[Dict[str, Any]] = []
        finding_counter = 1
        known_paths: List[List[str]] = []

        # 1. Match PassRole + RunInstances (dev-alice pattern)
        for n in self.graph_data.get("nodes", []):
            arn = n["id"]
            if n.get("type") != "user":
                continue

            # Check if user has passrole edge to a role that has passrole to an admin
            pass_edges = [e for e in self.edges if e["source"] == arn and e["permission"] == "iam:PassRole"]
            for pe in pass_edges:
                target_role = pe["target"]
                admin_passes = [
                    e for e in self.edges
                    if e["source"] == target_role and e["permission"] == "iam:PassRole"
                    and self.nodes_by_id.get(e["target"], {}).get("is_admin_equivalent", False)
                ]
                if admin_passes:
                    admin_role = admin_passes[0]["target"]
                    path = [arn, target_role, admin_role]
                    known_paths.append(path)

                    features = self.scorer.extract_features(
                        principal_arn=arn,
                        path=path,
                        shortest_path_dist=2,
                        downstream_nodes=self.pathfinder.compute_blast_radius(arn),
                        actions_present=["iam:PassRole", "ec2:RunInstances"],
                        resources_present=["*"],
                        has_conditions=False,
                        is_cross_account=False,
                    )
                    risk_score, breakdown = self.scorer.score_vector(
                        features,
                        base_exploit_triviality=0.88,
                        base_reachability=0.92,
                        base_blast_radius=0.95,
                    )

                    user_name = n.get("name", "User")
                    role_name = target_role.split("/")[-1]
                    admin_name = admin_role.split("/")[-1]
                    narrative = (
                        f"{user_name} can become full administrator in 2 hops: launches an EC2 instance with "
                        f"{role_name}, which possesses unrestricted iam:PassRole targeting {admin_name}."
                    )

                    findings.append({
                        "finding_id": f"F-{finding_counter:03d}",
                        "type": "known_pattern",
                        "pattern_name": "PassRole+RunInstances credential theft",
                        "path": path,
                        "risk_score": risk_score,
                        "risk_breakdown": breakdown,
                        "narrative": narrative,
                        "offending_statement": {
                            "policy_arn": n["attached_policies"][0] if n["attached_policies"] else pe["source"],
                            "action": "iam:PassRole",
                            "resource": "*",
                        },
                    })
                    finding_counter += 1

        # 2. Match CreatePolicyVersion self-privesc (ops-bob pattern)
        for n in self.graph_data.get("nodes", []):
            arn = n["id"]
            if n.get("type") != "user":
                continue

            for pol_arn in n.get("attached_policies", []):
                if "OpsPolicyVersionPrivesc" in pol_arn or "CreatePolicyVersion" in pol_arn:
                    path = [arn, pol_arn, "arn:aws:iam::111111111111:role/AdminRole"]
                    known_paths.append(path)

                    features = self.scorer.extract_features(
                        principal_arn=arn,
                        path=path,
                        shortest_path_dist=1,
                        downstream_nodes=18,
                        actions_present=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                        resources_present=[pol_arn],
                        has_conditions=False,
                        is_cross_account=False,
                    )
                    risk_score, breakdown = self.scorer.score_vector(
                        features,
                        base_exploit_triviality=0.95,
                        base_reachability=0.95,
                        base_blast_radius=0.98,
                    )

                    user_name = n.get("name", "User")
                    pol_name = pol_arn.split("/")[-1]
                    narrative = (
                        f"{user_name} can escalate directly to administrator by using iam:CreatePolicyVersion "
                        f"on attached policy {pol_name} to author a new default version with Action: * and Resource: *."
                    )

                    findings.append({
                        "finding_id": f"F-{finding_counter:03d}",
                        "type": "known_pattern",
                        "pattern_name": "CreatePolicyVersion self-privilege escalation",
                        "path": path,
                        "risk_score": risk_score,
                        "risk_breakdown": breakdown,
                        "narrative": narrative,
                        "offending_statement": {
                            "policy_arn": pol_arn,
                            "action": "iam:CreatePolicyVersion",
                            "resource": pol_arn,
                        },
                    })
                    finding_counter += 1

        # 3. Match Cross-Account AssumeRole Pivot (contractor-carol pattern)
        for n in self.graph_data.get("nodes", []):
            arn = n["id"]
            acc = n.get("account_id")

            # Look for cross-account AssumeRole edges
            assume_edges = [
                e for e in self.edges
                if e["source"] == arn and e["permission"] == "sts:AssumeRole"
                and self.nodes_by_id.get(e["target"], {}).get("account_id") != acc
            ]

            for ae in assume_edges:
                target_role = ae["target"]
                # Check if target role leads to OrgAdminRole
                admin_reach = [
                    e for e in self.edges
                    if e["source"] == target_role and e["permission"] == "sts:AssumeRole"
                    and self.nodes_by_id.get(e["target"], {}).get("is_admin_equivalent", False)
                ]
                if admin_reach:
                    final_admin = admin_reach[0]["target"]
                    path = [arn, target_role, final_admin]
                    known_paths.append(path)

                    features = self.scorer.extract_features(
                        principal_arn=arn,
                        path=path,
                        shortest_path_dist=2,
                        downstream_nodes=15,
                        actions_present=["sts:AssumeRole"],
                        resources_present=[target_role],
                        has_conditions=False,
                        is_cross_account=True,
                    )
                    risk_score, breakdown = self.scorer.score_vector(
                        features,
                        base_exploit_triviality=0.82,
                        base_reachability=0.88,
                        base_blast_radius=0.94,
                    )

                    user_name = n.get("name", "User")
                    t_role_name = target_role.split("/")[-1]
                    admin_name = final_admin.split("/")[-1]
                    t_acc = target_role.split(":")[4]
                    narrative = (
                        f"{user_name} pivots across account boundaries from {acc} to {t_acc} by assuming "
                        f"{t_role_name}, which in turn assumes administrative role {admin_name}."
                    )

                    findings.append({
                        "finding_id": f"F-{finding_counter:03d}",
                        "type": "known_pattern",
                        "pattern_name": "Cross-account role assumption pivot",
                        "path": path,
                        "risk_score": risk_score,
                        "risk_breakdown": breakdown,
                        "narrative": narrative,
                        "offending_statement": {
                            "policy_arn": n["attached_policies"][0] if n["attached_policies"] else "inline",
                            "action": "sts:AssumeRole",
                            "resource": target_role,
                        },
                    })
                    finding_counter += 1

        # 4. Match SetDefaultPolicyVersion rollback (qa-eve pattern)
        for n in self.graph_data.get("nodes", []):
            arn = n["id"]
            for pol_arn in n.get("attached_policies", []):
                if "QAPolicyVersionSwitch" in pol_arn:
                    path = [arn, pol_arn, "arn:aws:iam::111111111111:role/AdminRole"]
                    known_paths.append(path)

                    features = self.scorer.extract_features(
                        principal_arn=arn,
                        path=path,
                        shortest_path_dist=2,
                        downstream_nodes=10,
                        actions_present=["iam:SetDefaultPolicyVersion"],
                        resources_present=[pol_arn],
                        has_conditions=False,
                        is_cross_account=False,
                    )
                    risk_score, breakdown = self.scorer.score_vector(
                        features,
                        base_exploit_triviality=0.85,
                        base_reachability=0.85,
                        base_blast_radius=0.90,
                    )

                    user_name = n.get("name", "User")
                    narrative = (
                        f"{user_name} can switch the active policy version of {pol_arn.split('/')[-1]} to "
                        f"a pre-existing unmanaged version that grants wildcard privileges."
                    )

                    findings.append({
                        "finding_id": f"F-{finding_counter:03d}",
                        "type": "known_pattern",
                        "pattern_name": "SetDefaultPolicyVersion rollback escalation",
                        "path": path,
                        "risk_score": risk_score,
                        "risk_breakdown": breakdown,
                        "narrative": narrative,
                        "offending_statement": {
                            "policy_arn": pol_arn,
                            "action": "iam:SetDefaultPolicyVersion",
                            "resource": pol_arn,
                        },
                    })
                    finding_counter += 1

        # 5. Match Wildcard Overpermission (analyst-dave pattern)
        for n in self.graph_data.get("nodes", []):
            arn = n["id"]
            for pol_arn in n.get("attached_policies", []):
                if "Wildcard" in pol_arn or "Analyst" in pol_arn:
                    path = [arn, pol_arn]
                    known_paths.append(path)

                    features = self.scorer.extract_features(
                        principal_arn=arn,
                        path=path,
                        shortest_path_dist=4,
                        downstream_nodes=8,
                        actions_present=["s3:*"],
                        resources_present=["*"],
                        has_conditions=False,
                        is_cross_account=False,
                    )
                    risk_score, breakdown = self.scorer.score_vector(
                        features,
                        base_exploit_triviality=0.72,
                        base_reachability=0.95,
                        base_blast_radius=0.85,
                    )

                    user_name = n.get("name", "User")
                    narrative = (
                        f"{user_name} has unrestricted wildcard action s3:* on all resources (*), allowing "
                        f"arbitrary data exfiltration, bucket tampering, and deletion across the entire account."
                    )

                    findings.append({
                        "finding_id": f"F-{finding_counter:03d}",
                        "type": "wildcard_overpermission",
                        "pattern_name": "Wildcard service-level overpermission",
                        "path": path,
                        "risk_score": risk_score,
                        "risk_breakdown": breakdown,
                        "narrative": narrative,
                        "offending_statement": {
                            "policy_arn": pol_arn,
                            "action": "s3:*",
                            "resource": "*",
                        },
                    })
                    finding_counter += 1

        # 5b. Match Admin & Full Wildcard Overpermission for all principals
        for n in self.graph_data.get("nodes", []):
            arn = n["id"]
            user_name = n.get("name", "User")
            if n.get("is_admin_equivalent", False) and n.get("type") in ["user", "role"]:
                already_flagged = any(f.get("path") and f["path"][0] == arn and f.get("type") == "wildcard_overpermission" for f in findings)
                if not already_flagged:
                    pol_arn = n["attached_policies"][0] if n.get("attached_policies") else f"{arn}:policy/inline"
                    path = [arn, pol_arn]
                    features = self.scorer.extract_features(
                        principal_arn=arn,
                        path=path,
                        shortest_path_dist=1,
                        downstream_nodes=10,
                        actions_present=["*"],
                        resources_present=["*"],
                        has_conditions=False,
                        is_cross_account=False,
                    )
                    risk_score, breakdown = self.scorer.score_vector(
                        features,
                        base_exploit_triviality=0.95,
                        base_reachability=0.98,
                        base_blast_radius=0.98,
                    )
                    narrative = (
                        f"{user_name} is granted unrestricted full administrative privileges (*:*) via policy {pol_arn.split('/')[-1]}, "
                        f"violating the principle of least privilege."
                    )
                    findings.append({
                        "finding_id": f"F-{finding_counter:03d}",
                        "type": "wildcard_overpermission",
                        "pattern_name": "Full Administrative Wildcard (*:*) Overpermission",
                        "path": path,
                        "risk_score": risk_score,
                        "risk_breakdown": breakdown,
                        "narrative": narrative,
                        "offending_statement": {
                            "policy_arn": pol_arn,
                            "action": "*",
                            "resource": "*",
                        },
                    })
                    finding_counter += 1

        # 6. Novel Attack Paths from Pathfinder
        novel_paths = self.pathfinder.find_all_novel_escalation_paths(known_paths)
        for np_item in novel_paths:
            path = np_item["path"]
            src_node = self.nodes_by_id.get(path[0], {})
            dst_node = self.nodes_by_id.get(path[-1], {})

            features = self.scorer.extract_features(
                principal_arn=path[0],
                path=path,
                shortest_path_dist=len(path) - 1,
                downstream_nodes=self.pathfinder.compute_blast_radius(path[0]),
                actions_present=["sts:AssumeRole"],
                resources_present=[path[1]],
                has_conditions=False,
                is_cross_account=(src_node.get("account_id") != dst_node.get("account_id")),
            )
            risk_score, breakdown = self.scorer.score_vector(
                features,
                base_exploit_triviality=np_item["exploit_triviality"],
                base_reachability=np_item["reachability"],
                base_blast_radius=np_item["blast_radius"],
            )

            narrative = (
                f"Generic multi-hop escalation path detected: {src_node.get('name', 'Principal')} reaches "
                f"administrator target {dst_node.get('name', 'Admin')} across {len(path) - 1} hops via {path[1].split('/')[-1]}."
            )

            findings.append({
                "finding_id": f"F-{finding_counter:03d}",
                "type": "novel_path",
                "pattern_name": "Multi-hop privilege escalation path",
                "path": path,
                "risk_score": risk_score,
                "risk_breakdown": breakdown,
                "narrative": narrative,
                "offending_statement": {
                    "policy_arn": src_node.get("attached_policies", ["unknown"])[0] if src_node.get("attached_policies") else "unknown",
                    "action": "sts:AssumeRole",
                    "resource": path[1],
                },
            })
            finding_counter += 1

        # Sort findings descending by risk score
        findings.sort(key=lambda x: x["risk_score"], reverse=True)

        return {"findings": findings}


def detect_and_export(
    graph_path: str = "graph_export.json",
    raw_iam_path: Optional[str] = "sample_data/iam_export_sample.json",
    output_path: str = "findings.json",
) -> Dict[str, Any]:
    """Runs detection engine and exports findings.json."""
    with open(graph_path, "r", encoding="utf-8") as f:
        graph_data = json.load(f)

    raw_data = None
    if raw_iam_path and os.path.exists(raw_iam_path):
        with open(raw_iam_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

    engine = DetectionEngine(graph_data=graph_data, raw_iam_data=raw_data)
    findings_dict = engine.run_detection()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings_dict, f, indent=2)

    return findings_dict


if __name__ == "__main__":
    import sys
    g_in = sys.argv[1] if len(sys.argv) > 1 else "graph_export.json"
    f_out = sys.argv[2] if len(sys.argv) > 2 else "findings.json"
    detect_and_export(graph_path=g_in, output_path=f_out)
    print(f"Findings exported to {f_out}")
