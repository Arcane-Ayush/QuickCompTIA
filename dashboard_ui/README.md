# Person 4 — Interactive Dashboard & Visualization (`dashboard_ui`)

## What this module does
The **Interactive Dashboard & Visualization** module is the frontend interface for the Cloud IAM Misconfiguration Detector. It presents:
1. **Interactive Privilege Graph**: Visualizes IAM entities (users, roles, policies, resources) using Vis.js network layout with risk color coding and attack path highlighting.
2. **Explainable Risk Scorecards**: Displays ranked findings with 3-factor risk breakdown (Reachability, Blast Radius, Exploit Triviality).
3. **Attack Narrative & Diff Viewer**: Displays plain-English attack narratives and side-by-side policy diffs (Offending Policy vs. Least-Privilege Remediation).
4. **Actionable Fix Export**: Allows one-click downloading of generated least-privilege policy replacement JSON files.

---

## How to run it standalone

Start local HTTP server:
```bash
python -m dashboard_ui.server --port 8080
```
Then open `http://localhost:8080` in your web browser.

Alternatively, open `dashboard_ui/index.html` directly in any web browser (static file mode).

---

## Input file(s) expected and where

- **Files**: `graph_export.json`, `findings.json`, `remediations.json`
- **Location**: Root directory of the repository or served via `/api/data` endpoint.
- **Schemas**:
  - `graph_export.json` (Section 2.1 schema)
  - `findings.json` (Section 2.2 schema)
  - `remediations.json` (Section 2.3 schema)

---

## Output file produced and where

- Terminal stage module — renders interactive UI in browser.
- Produces client-side downloadable policy fix JSON files (e.g., `remediation_F-001.json`, `all_remediations.json`).

---

## Known limitations / things not implemented
- Automatic real-time WebSocket push updates (currently uses polling/fetch refresh button).
