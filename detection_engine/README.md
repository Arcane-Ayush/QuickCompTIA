# Person 2 — Detection Engine & Machine Learning Risk Scorer (`/detection_engine/`)

## What this module does
Identifies IAM misconfigurations, privilege escalation attack paths, and over-permissive wildcard statements using a hybrid analytical engine:
1. **Declarative Rule Matcher**: Evaluates JSON rule signatures located in `/detection_engine/rules/` modeling Rhino Security Labs and Bishop Fox attack vectors (e.g. `PassRole+RunInstances`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `CrossAccountTrust`).
2. **NetworkX Graph Pathfinder**: Traverses identity relations using BFS and shortest path algorithms to identify novel multi-hop escalation paths leading to administrator-equivalent principals.
3. **Machine Learning Model (`RandomForestClassifier`)**: Scikit-learn model trained on IAM feature vectors (wildcards, sensitive IAM action counts, shortest path to admin, blast radius, conditions) to score exploit triviality and anomaly probability.
4. **Explainable Composite Risk Formula**: `Risk = Reachability × Blast_radius × Exploit_triviality` (0–100 scale), accompanied by the 3-factor breakdown for full transparency.
5. **Attack Story Narratives**: Generates deterministic plain-English attack narratives for each finding.

## How to run it standalone
1. Train the ML model (if not already trained):
```bash
python -m detection_engine.train_model
```
2. Run detection on graph export:
```bash
python -m detection_engine.detector graph_export.json findings.json
```

## Input file(s) expected and where
- `graph_export.json`: Graph nodes, edges, and account metadata produced by Person 1.
- `sample_data/iam_export_sample.json`: Raw IAM authorization export (optional context for policy details).
- `detection_engine/rules/*.json`: Declarative rule files.
- `detection_engine/models/iam_risk_classifier.pkl`: Trained ML model weights.

## Output file produced and where
- `findings.json`: Strictly adheres to Section 2.2 schema containing `findings` with `finding_id`, `type`, `pattern_name`, `path`, `risk_score`, `risk_breakdown`, `narrative`, and `offending_statement`.

## Known limitations / things not implemented
- Dynamic IAM condition operators (e.g. `aws:EpochTime` or ephemeral tags) are evaluated statically based on presence and type.
