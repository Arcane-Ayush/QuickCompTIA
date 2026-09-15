# Dashboard UI — Person 4 Module

## What this module does

Interactive web dashboard for the Cloud IAM Misconfiguration Detector pipeline. It is the **terminal stage** — it consumes the JSON outputs of Persons 1, 2, and 3 and renders them as an explorable, visual interface.

### Features
- **Interactive Graph Visualization** (Cytoscape.js): renders `graph_export.json` as a navigable network graph. Nodes are color-coded by type (user, role, group, policy, resource) and shaped distinctly. Admin-equivalent nodes have a red border glow. Edges are styled by permission type (AssumeRole = solid purple, PassRole = dashed orange, wildcard = red).
- **Risk Scorecards**: ranked list of security findings from `findings.json`, sorted by `risk_score` descending. Each card shows the pattern name, type badge, animated risk bar, and the **3-factor risk breakdown** (reachability, blast radius, exploit triviality) — the score is always explainable, never a black-box number.
- **Click-to-Expand Detail Drawer**: clicking a finding opens a slide-in panel showing the plain-English attack narrative, the escalation path as a visual breadcrumb, the offending policy statement, and (if available) a side-by-side original vs. suggested remediation comparison from `remediations.json`.
- **Download Fixed Policy**: one-click download of the auto-generated least-privilege policy statement as a ready-to-apply JSON file.
- **Node ↔ Finding Cross-Linking**: clicking a graph node highlights all related findings in the scorecard; clicking a finding highlights its attack path in the graph.

### What this module does NOT do
- **No detection, scoring, or remediation logic.** This module only displays data produced by Persons 1–3. If a risk score, narrative, or remediation is incorrect, it must be fixed in the upstream module (Person 2 or 3), not patched in the UI.

## How to run it standalone

### Prerequisites
- A modern web browser (Chrome, Firefox, Edge)
- A local HTTP server (needed because `fetch()` doesn't work over `file://`)

### Steps

1. **Navigate to the dashboard_ui directory:**
   ```bash
   cd dashboard_ui
   ```

2. **Start a local HTTP server:**
   ```bash
   # Python 3 (simplest)
   python -m http.server 8080

   # OR Node.js
   npx serve .

   # OR any other static file server
   ```

3. **Open in browser:**
   ```
   http://localhost:8080
   ```

4. **Load data:**
   - **Option A — Built-in demo data:** Click the **"Load Built-in Demo Data"** button on the file loader screen. This loads the stub JSON files from `data/` automatically.
   - **Option B — Upload your own files:** Use the three file inputs to load `graph_export.json`, `findings.json`, and `remediations.json` from the pipeline output. All three files must be loaded before the dashboard renders.

5. **Interact:**
   - Click finding cards in the right panel → opens the detail drawer with narrative + remediation.
   - Click nodes in the graph → highlights related findings.
   - Use the zoom/fit/reset buttons in the top-right of the graph panel.
   - Press **Escape** or click the overlay to close the detail drawer.

## Input file(s) expected and where

| File | Schema | Source |
|---|---|---|
| `graph_export.json` | Section 2.1 of build protocol | Person 1 (Parser & Graph Builder) |
| `findings.json` | Section 2.2 of build protocol | Person 2 (Detection Engine) |
| `remediations.json` | Section 2.3 of build protocol | Person 3 (Remediation Generator) |

These can be loaded via the file picker UI or fetched from `data/` (stub versions included for standalone development).

## Output file produced and where

This module is the **terminal pipeline stage** — it does not produce an output file consumed by other modules. It produces:
- A rendered interactive web dashboard (in-browser)
- On-demand: downloadable fixed policy JSON files (via the "Download Fixed Policy" button in the detail drawer)

## Known limitations / things not implemented

- **Static-file mode only** (Definition of Done baseline). Live pipe from Person 1–3's code is a stretch goal.
- **No server-side component** — the dashboard is entirely client-side. Integration into `app.py` would use `python -m http.server` or a Flask static route.
- **Layout algorithm** (`cose-bilkent`) may produce suboptimal arrangements for very large graphs (50+ nodes). For large datasets, `dagre` (hierarchical) could be swapped in as a one-line change in `js/graph.js`.
- **No filtering/search** on findings or graph nodes — stretch goal.
- **No export to PDF/PNG** of the graph — stretch goal.

## File structure

```
dashboard_ui/
├── README.md                           ← this file
├── index.html                          ← main entry point
├── css/
│   └── styles.css                      ← full design system
├── js/
│   ├── app.js                          ← application controller & file loader
│   ├── graph.js                        ← Cytoscape.js graph renderer
│   ├── scorecards.js                   ← risk scorecard panel
│   └── detail-modal.js                 ← click-to-expand detail drawer
└── data/
    ├── stub_graph_export.json          ← mock data (Section 2.1)
    ├── stub_findings.json              ← mock data (Section 2.2)
    └── stub_remediations.json          ← mock data (Section 2.3)
```
