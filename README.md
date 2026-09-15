# Cloud IAM Misconfiguration Detector & ML Risk Engine

An end-to-end security analysis pipeline and visualization dashboard for detecting AWS IAM misconfigurations, multi-hop privilege escalation attack paths, and over-permissive wildcard grants.

Built following a strict 4-stage modular pipeline architecture:
```
┌─────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│ Person 1        │      │ Person 2                │      │ Person 3                │      │ Person 4                │
│ Parser & Graph  │ ───► │ Detection & ML Scoring  │ ───► │ Remediation Generator   │ ───► │ Interactive Dashboard   │
│ (NetworkX)      │      │ (Rules + Pathfinder+ML) │      │ (Policy-Sentry Auto-Fix)│      │ (Cytoscape.js & Cards)  │
└─────────────────┘      └─────────────────────────┘      └─────────────────────────┘      └─────────────────────────┘
```

---

## ⚡ Quick Start

### 1. Prerequisites
Ensure Python 3.10+ is installed. Install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Train the Machine Learning Risk Model
Train the Random Forest classifier on IAM permission profiles and topology features:
```bash
python -m detection_engine.train_model
```
Outputs trained weights to `detection_engine/models/iam_risk_classifier.pkl` and metadata metrics to `model_metadata.json`.

### 3. Run the Full Analysis Pipeline
Run the end-to-end analysis on realistic multi-account AWS authorization data:
```bash
python main.py --train --input sample_data/iam_export_sample.json
```
This automatically:
- Parses IAM authorization details and constructs a directed NetworkX graph (`graph_export.json`).
- Executes declarative rule signatures (Rhino Security / Bishop Fox patterns) and BFS attack pathfinding.
- Computes explainable 3-factor composite risk scores (`Risk = Reachability × Blast_radius × Exploit_triviality`).
- Synthesizes scoped, least-privilege replacement policies with condition keys (`remediations.json`).
- Validates all generated JSON artifacts against formal JSON schemas in `/schemas/`.
- Syncs outputs directly to `dashboard_ui/data/` for live visualization.

### 4. Launch the Interactive Dashboard
Serve the dashboard locally:
```bash
python -m http.server 8080 --directory dashboard_ui
```
Open your browser to: **`http://localhost:8080`**
- Click **"⚡ Load Real IAM Scan Results"** to visualize all 22+ principals, accounts, and detected escalation paths.
- Explore the interactive Cytoscape.js attack graph with zoom/pan and automatic layout.
- Click any finding card to highlight the full attack vector and review the auto-generated remediation policy.

---

## 📂 Repository Structure

- `sample_data/`: Realistic AWS IAM authorization export (`GetAccountAuthorizationDetails`).
- `parser_graph/`: Person 1 module — IAM policy statement normalizer and NetworkX graph builder.
- `detection_engine/`: Person 2 module — Declarative rules (`rules/`), ML model training (`train_model.py`), pathfinder (`pathfinder.py`), and risk scorer (`ml_scorer.py`).
- `remediation_generator/`: Person 3 module — Least-privilege policy auto-fix synthesizer (`generator.py`).
- `dashboard_ui/`: Person 4 module — Cytoscape.js interactive visualization and explainable risk scorecards.
- `schemas/`: Formal JSON schema specifications for all pipeline contracts.
- `main.py`: Shared orchestrator running the full pipeline end-to-end.
