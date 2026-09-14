# Person 2 — Detection Engine & Risk Scorer

## What this module does
The **Detection Engine & Risk Scorer** is the analytical core of the Cloud IAM Misconfiguration Detector. It accepts an authorization graph exported by Person 1 and detects security risks using three specialized analysis engines:
1. **Declarative Known-Pattern Matcher**: Evaluates 7 Rhino Security Labs & Bishop Fox privilege escalation vectors (e.g. `PassRole+RunInstances`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `CreateAccessKey`, `sts:AssumeRole`, `AttachUserPolicy`, `PutUserPolicy`) encoded strictly as data files in `rules/iam_privesc_rules.json`.
2. **Generic Graph Pathfinder**: Executes graph pathfinding (BFS/Dijkstra) from every non-admin principal (`is_admin_equivalent == false`) to admin-equivalent targets (`is_admin_equivalent == true`), discovering novel and multi-hop attack paths missed by static rules.
3. **Wildcard & Over-Permission Scorer**: Scans for `Action: "*"` / `<service>:*` and `Resource: "*"` grants independent of exploitability.
4. **Composite Risk Scorer**: Calculates explainable, non-blackbox risk scores using the formula:
   $$\text{Risk} = \text{Reachability} \times \text{Blast Radius} \times \text{Exploit Triviality} \times 100$$
   Every finding includes the decomposed 3-factor breakdown.
5. **Deterministic Narrative Generator**: Constructs plain-English attack narratives for presentation and dashboard rendering.

## How to run it standalone
Run the detector CLI from the repository root:
```bash
python -m detection_engine.detector --input detection_engine/tests/test_graph_export.json --output detection_engine/findings.json
```

To run the automated unit test suite:
```bash
python -m unittest detection_engine/tests/test_detector.py
```

To use as a Python module:
```python
from detection_engine import run_detection

results = run_detection(
    input_graph_path="graph_export.json",
    output_findings_path="findings.json"
)
print(f"Discovered {len(results['findings'])} findings")
```

## Input file(s) expected and where
- **File**: `graph_export.json`
- **Location**: Provided via `--input` flag (root directory in integrated pipeline, or `detection_engine/tests/test_graph_export.json` for standalone testing).
- **Schema**: Section 2.1 JSON contract containing:
  - `accounts`: list of account IDs
  - `nodes`: list of principal/policy/resource nodes with `id`, `type`, `account_id`, `name`, `attached_policies`, `is_admin_equivalent`
  - `edges`: list of directed edges with `source`, `target`, `permission`, `condition`, `is_wildcard_resource`

## Output file produced and where
- **File**: `findings.json`
- **Location**: Written to path specified by `--output` flag (defaults to `findings.json` or `detection_engine/findings.json`).
- **Schema**: Strictly adheres to Section 2.2 contract:
  - `findings`: Array of finding objects with:
    - `finding_id` (e.g. `F-001`, `F-002`)
    - `type` (`known_pattern` | `novel_path` | `wildcard_overpermission`)
    - `pattern_name` (descriptive name)
    - `path` (list of ARNs/nodes traversed)
    - `risk_score` (0.0 to 100.0)
    - `risk_breakdown` (`reachability`, `blast_radius`, `exploit_triviality` floats between 0.0 and 1.0)
    - `narrative` (plain-English attack explanation)
    - `offending_statement` (`policy_arn`, `action`, `resource`)

## Known limitations / things not implemented
- Service Control Policies (SCPs) and Permission Boundaries are represented if flattened by Person 1's graph builder, but condition logic evaluation currently treats conditions as complexity penalties rather than full boolean satisfiability solvers.
- Outbound multi-hop pathfinding limits path depth cutoff to 4 hops for high performance across large enterprise graphs.
