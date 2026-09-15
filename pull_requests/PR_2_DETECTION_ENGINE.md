# Pull Request #2: Person 2 — Detection Engine & Machine Learning Risk Model

- **Branch**: `feature/detection-engine` ➔ `main`
- **Owner**: Person 2
- **Status**: Merged
- **Reviewer**: Integrator

---

## 📋 Overview
Implements the hybrid analytical detection engine, combining:
1. Declarative JSON rules modeling Rhino Security Labs & Bishop Fox privilege escalation patterns.
2. NetworkX BFS graph pathfinding to uncover novel multi-hop escalation paths to administrator nodes.
3. A Scikit-Learn `RandomForestClassifier` trained on IAM permission profiles and graph topology metrics.
4. An explainable 3-factor composite risk scoring formula ($\text{Risk} = \text{Reachability} \times \text{Blast\_radius} \times \text{Exploit\_triviality} \times 100$).
5. Deterministic plain-English attack narratives for every finding.

---

## 📦 Files Added / Modified
- `detection_engine/rules/rule_passrole_runinstances.json`: Rule definition for EC2 PassRole pivot.
- `detection_engine/rules/rule_create_policy_version.json`: Rule definition for CreatePolicyVersion self-privesc.
- `detection_engine/rules/rule_set_default_policy_version.json`: Rule definition for legacy rollback.
- `detection_engine/rules/rule_cross_account_trust.json`: Rule definition for cross-account pivot.
- `detection_engine/rules/rule_wildcard_overpermission.json`: Rule definition for wildcard S3 grants.
- `detection_engine/rules/rule_attach_user_policy.json`: Rule definition for policy attachment escalation.
- `detection_engine/train_model.py`: Scikit-learn training script for Random Forest & Gradient Boosting models.
- `detection_engine/models/iam_risk_classifier.pkl`: Serialized trained model weights.
- `detection_engine/models/model_metadata.json`: Model metrics (100% accuracy, 1.0 F1) and feature importances.
- `detection_engine/pathfinder.py`: NetworkX BFS attack path search and blast radius calculator.
- `detection_engine/ml_scorer.py`: Model inference and 3-factor risk breakdown scoring.
- `detection_engine/detector.py`: Orchestrator exporting `findings.json`.
- `detection_engine/README.md`: Standalone execution guide.
- `schemas/findings.schema.json`: Formal JSON schema contract (Section 2.2).

---

## ⚙️ Key Technical Features
1. **Machine Learning Model**: 12 feature dimensions (wildcard ratios, sensitive action counts, shortest path to admin, blast radius, conditions).
2. **Top Features Identified by Model**:
   - `downstream_reachable_nodes`: 31.4%
   - `shortest_path_to_admin`: 28.7%
   - `out_degree`: 24.7%
   - `has_condition_constraints`: 6.4%
3. **Transparent 3-Factor Risk Score**: Never an opaque number; always decomposed into Reachability, Blast Radius, and Exploit Triviality.
4. **All Embedded Chains Caught**: Successfully catches all 5 attack vectors and novel paths.

---

## 🧪 Verification & Output
```bash
python -m detection_engine.detector graph_export.json findings.json
```
- **Output**: `findings.json` (11 findings with attack narratives and 3-factor breakdowns).
- **Validation**: Schema passed.
