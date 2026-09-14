# Cloud IAM Misconfiguration Detector

A multi-module pipeline that parses AWS IAM configurations, detects privilege
escalation paths using graph reachability analysis, generates least-privilege
remediation suggestions, and visualizes findings in an interactive dashboard.

## Pipeline

```
Person 1 (Parser)  →  Person 2 (Detection)  →  Person 3 (Remediation)  →  Person 4 (Dashboard)
graph_export.json      findings.json              remediations.json          browser UI
```

## Quick Start (Integration)

```bash
pip install -r requirements.txt
python app.py  # runs the full pipeline on sample_data/iam_export_sample.json
```

## Module READMEs

- [parser_graph/README.md](parser_graph/README.md) — Person 1: Parser & Graph Builder
- [detection_engine/README.md](detection_engine/README.md) — Person 2: Detection Engine
- [remediation_generator/README.md](remediation_generator/README.md) — Person 3: Remediation Generator
- [dashboard_ui/README.md](dashboard_ui/README.md) — Person 4: Dashboard

## Schemas

JSON Schema contracts (Section 2 of the build protocol):

- [schemas/graph_export.schema.json](schemas/graph_export.schema.json)
- [schemas/findings.schema.json](schemas/findings.schema.json)
- [schemas/remediations.schema.json](schemas/remediations.schema.json)

## Branch Structure

| Branch | Owner | Folder |
|--------|-------|--------|
| `feature/parser-graph` | Person 1 | `/parser_graph/` |
| `feature/detection-engine` | Person 2 | `/detection_engine/` |
| `feature/remediation-generator` | Person 3 | `/remediation_generator/` |
| `feature/dashboard-ui` | Person 4 | `/dashboard_ui/` |
| `main` | Integrator | (all merged) |

> **Nobody pushes directly to `main`.** See the build protocol for branch and merge rules.

