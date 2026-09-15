# CLOUD IAM MISCONFIGURATION DETECTOR — MULTI-AGENT BUILD PROTOCOL
### Strict Execution Document — 4-Person Parallel Build

> **READ THIS FIRST:** This document is the single source of truth for how this project gets built. Every person/agent works from THIS file. Nobody improvises scope. Nobody touches another person's folder. Nobody merges without the integration checklist passing. If something in your reality contradicts this doc, STOP and raise it in the team channel before you diverge — do not silently "fix it your way."

---

## 0. Global Rules (apply to all 4 people — no exceptions)

1. **One person = one module = one branch = one folder.** You own your folder completely. You NEVER edit, refactor, rename, or "clean up" a file inside another person's folder — not even a typo fix. If you find a bug in someone else's module, you report it (issue / message), you do not patch it yourself.
2. **The interface contract in Section 2 is LAW.** Your module's inputs and outputs must match the JSON schemas defined there EXACTLY (field names, types, casing). This is what allows 4 people to build in isolation and have it click together at the end without a rewrite. If you think the contract needs to change, that requires all 4 people to agree in the group chat first, then Person 1 updates this document and pings everyone — nobody changes the contract unilaterally.
3. **No shared files get edited without asking.** `main.py` / `app.py` (root orchestrator), `requirements.txt`, `schemas/`, and this document are shared. Any edit to a shared file must be announced in the group chat BEFORE you push, with a one-line reason.
4. **Branch discipline (mandatory, even if you're not comfortable with git):**
   - `main` branch = only working, integrated code. Nobody pushes directly to `main`. Ever.
   - Each person works ONLY on their own branch: `feature/parser-graph`, `feature/detection-engine`, `feature/remediation-generator`, `feature/dashboard-ui`.
   - Commit small, commit often, with a plain message describing what changed (`added wildcard regex check`, not `update`).
   - When your module works standalone (see your Definition of Done), you open a Pull Request into `main`. You do NOT merge your own PR — the designated Integrator (Section 5) reviews and merges.
   - If git feels intimidating: it is OK to just re-save/re-upload your folder's contents to your branch daily and message the group — consistency matters more than git elegance. Nobody will be penalized for messy commit history. Silence and untracked local-only work for days IS penalized, because it blocks integration.
5. **Test against the sample data, not a real AWS account.** A shared `sample_data/iam_export_sample.json` (mock `GetAccountAuthorizationDetails`-style export, modeled on the Bishop Fox `iam-vulnerable` fixture) will be provided by Person 1 by the deadline in Section 6. Everyone builds and validates against this file so all 4 modules agree on what "real" input looks like.
6. **Deadlines are hard.** Late delivery of your module's output contract blocks the other 3 people, because Detection needs Parser's graph, Remediation needs Detection's findings, Dashboard needs both. See Section 6 for the dependency chain and dates.
7. **No scope creep, no gold-plating.** Build exactly what your role section says, to the "Definition of Done" bar, and STOP. Extra polish happens only after all 4 modules integrate and there's time left before the deadline. A working end-to-end demo beats one beautiful module and three unfinished ones.
8. **Document as you go.** Every function you write gets a one-line docstring. Every module folder gets a `README.md` (template in Section 4) explaining how to run it standalone. The Integrator and the deck/video person will use these — do not assume "I'll explain it live," because you may not be the one presenting that part.
9. **AI-assistance framing:** if you use an LLM to generate a component (e.g. narrative generation in Detection, or code scaffolding), that is fine and expected — but you are responsible for testing and understanding every line before it ships. "The AI wrote it" is not an acceptable answer if it's wrong or unexplainable to a judge.

---

## 1. Team Structure & Pipeline

The system is one pipeline, split into 4 independently buildable stages:

```
PERSON 1                PERSON 2                  PERSON 3                    PERSON 4
Parser + Graph    →     Detection Engine     →     Remediation Generator       Dashboard/UI
Builder                 (escalation finder,        (least-privilege policy     (consumes Person 2's
                         wildcard scorer,           auto-fix generator)         findings + Person 1's
                         risk scorer)                                          graph + Person 3's fixes)
```

Person 4's dashboard is the "front window" that queries/loads the outputs of 1, 2, and 3 — it does NOT reimplement any detection or graph logic itself.

| # | Role | Branch name | Folder owned |
|---|---|---|---|
| 1 | Parser & Graph Builder | `feature/parser-graph` | `/parser_graph/` |
| 2 | Detection Engine & Risk Scorer | `feature/detection-engine` | `/detection_engine/` |
| 3 | Least-Privilege Remediation Generator | `feature/remediation-generator` | `/remediation_generator/` |
| 4 | Interactive Dashboard & Visualization | `feature/dashboard-ui` | `/dashboard_ui/` |

---

## 2. Interface Contract (the glue — do not deviate)

Every module reads/writes JSON matching these shapes. Put the schema files in `/schemas/` (shared, read-only for everyone except Person 1, who authors v1 and updates only with group sign-off).

### 2.1 Output of Person 1 (Parser + Graph Builder) → `graph_export.json`
Consumed by Person 2 and Person 4.
```json
{
  "accounts": ["111111111111", "222222222222"],
  "nodes": [
    {
      "id": "arn:aws:iam::111111111111:user/dev-alice",
      "type": "user | role | group | policy | resource",
      "account_id": "111111111111",
      "name": "dev-alice",
      "attached_policies": ["arn:aws:iam::111111111111:policy/DevPolicy"],
      "is_admin_equivalent": false
    }
  ],
  "edges": [
    {
      "source": "arn:aws:iam::111111111111:user/dev-alice",
      "target": "arn:aws:iam::111111111111:role/AdminRole",
      "permission": "sts:AssumeRole | iam:PassRole | policy_attachment | group_membership",
      "condition": null,
      "is_wildcard_resource": false
    }
  ]
}
```
- Node `type` and edge `permission` values must come from the fixed enums above — no free text.
- `is_admin_equivalent` must be pre-computed by Person 1 (true if the principal's effective policy allows `*:*` or has `AdministratorAccess` attached) — Person 2 relies on this flag as pathfinding targets.

### 2.2 Output of Person 2 (Detection Engine) → `findings.json`
Consumed by Person 3 and Person 4.
```json
{
  "findings": [
    {
      "finding_id": "F-001",
      "type": "known_pattern | novel_path | wildcard_overpermission",
      "pattern_name": "PassRole+RunInstances credential theft",
      "path": ["arn:...:user/dev-alice", "arn:...:role/AdminRole"],
      "risk_score": 87.5,
      "risk_breakdown": {"reachability": 0.9, "blast_radius": 0.95, "exploit_triviality": 0.85},
      "narrative": "dev-alice can become admin in 2 hops: assumes DevRole, then passes AdminRole to a new EC2 instance.",
      "offending_statement": {
        "policy_arn": "arn:aws:iam::111111111111:policy/DevPolicy",
        "action": "iam:PassRole",
        "resource": "*"
      }
    }
  ]
}
```
- `risk_score` is 0–100, always accompanied by the 3-factor `risk_breakdown` (so the score is explainable, never a black box — this is a strictness requirement, not a suggestion).
- `finding_id` must be stable and unique — Person 3 and Person 4 reference findings by this ID.

### 2.3 Output of Person 3 (Remediation Generator) → `remediations.json`
Consumed by Person 4.
```json
{
  "remediations": [
    {
      "finding_id": "F-001",
      "original_statement": {"action": "iam:PassRole", "resource": "*"},
      "suggested_statement": {
        "action": "iam:PassRole",
        "resource": "arn:aws:iam::111111111111:role/AppRole-*",
        "condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
      },
      "justification": "Restricts PassRole to only the application role prefix and only when passed to EC2, closing the unrestricted admin-role pivot."
    }
  ]
}
```
- One remediation object per finding that is fixable (wildcard/over-permission and known-pattern types). Novel-path findings may be flagged `"remediable": false` with a reason instead.

### 2.4 Dashboard (Person 4) contract
Person 4 does not produce a file others consume — it is the terminal stage. It MUST be able to run against `graph_export.json` + `findings.json` + `remediations.json` as static files (so it can be built and demoed even if another module is mid-integration) and, if time allows, also support a live pipe from Persons 1–3's code directly. Static-file mode is the Definition-of-Done baseline; live mode is a stretch goal, not required for the core deadline.

---

## 3. Per-Person Role Briefs

### PERSON 1 — Parser & Graph Builder
**You are the foundation. Everyone waits on your schema and sample data first.**

Scope (build exactly this, nothing more):
- Parse a `GetAccountAuthorizationDetails`-style JSON export (users, roles, groups, inline + managed policies, trust policy documents).
- Normalize every policy statement into `(Effect, Principal, Action[], Resource[], Condition{})` tuples.
- Build a directed graph (NetworkX) with nodes = users/roles/groups/policies/resources, edges = policy attachment, group membership, `sts:AssumeRole` trust, `iam:PassRole` targets — each edge carries its permission and any condition block (edges are conditional/directional, never boolean adjacency).
- Compute `is_admin_equivalent` per principal.
- Export exactly the schema in Section 2.1 to `graph_export.json`.
- Produce `sample_data/iam_export_sample.json` — a small (15–30 principal) realistic mock dataset with at least 3 deliberately embedded escalation chains (PassRole+RunInstances, CreatePolicyVersion self-privesc, cross-account trust) so Person 2 has something real to detect against. **Deliver this file first, before anything else — it unblocks the other 3 people.**

Definition of Done: running your module standalone on the sample data produces a valid `graph_export.json` that passes the schema, and a `README.md` explaining how to run it and what the sample data's embedded escalation chains are (so Person 2 can verify their detector actually catches them).

Forbidden: writing any detection/pattern-matching logic, any risk scoring, any UI code.

---

### PERSON 2 — Detection Engine & Risk Scorer
**You are the analytical core. Do not start real work until Person 1's sample `graph_export.json` exists — build against a hand-made stub in the meantime if you're blocked.**

Scope:
- Known-pattern matcher: encode 5–8 Rhino Security Labs / Bishop Fox escalation patterns as declarative rules (YAML or JSON rule files under `/detection_engine/rules/`, not hardcoded in Python — this is a strictness requirement, rules must be data, not code, so adding a new pattern is a file edit).
- Generic graph pathfinder: BFS/Dijkstra from every non-admin principal to every `is_admin_equivalent: true` node, catching chains the pattern list didn't name.
- Wildcard/over-permission scorer: flag `Resource: "*"` and `service:*` grants independent of exploitability.
- Composite risk score: `Risk = Reachability × Blast_radius × Exploit_triviality`, always returned with the 3-factor breakdown — never a single opaque number.
- Plain-English narrative generator per finding (template-based or LLM-assisted — your choice, but it must be deterministic enough to demo reliably twice in a row).
- Export exactly the schema in Section 2.2 to `findings.json`.

Definition of Done: running your module on Person 1's sample data produces `findings.json` that (a) validates against the schema and (b) actually flags the 3+ embedded escalation chains Person 1 built into the sample data. If it misses one, that's a bug you fix before calling this done.

Forbidden: modifying the graph structure or schema from Person 1, writing remediation/policy-generation logic, writing UI code.

---

### PERSON 3 — Least-Privilege Remediation Generator
**You consume Person 2's findings; you do not need the full pipeline running to start — build against a hand-made stub `findings.json` matching Section 2.2 while waiting.**

Scope:
- For each wildcard/over-permission and known-pattern finding, generate a minimal-privilege replacement statement using a CRUD/ARN-scoped model (Policy-Sentry-style): replace `Action: "*"` or `service:*` with the specific actions actually implicated by the finding, and replace `Resource: "*"` with the narrowest ARN pattern that still satisfies the legitimate use case implied by the resource type.
- Write a one-sentence justification per remediation explaining what risk it closes.
- Export exactly the schema in Section 2.3 to `remediations.json`.
- Stretch (only after core is done): if CloudTrail-style "last used actions" mock data is available, cross-check suggested actions against it (Repokid-style usage-grounded trimming) — present as a bonus feature only if time allows, do not let this block core delivery.

Definition of Done: running your module on Person 2's sample `findings.json` produces `remediations.json` that validates against the schema, with a suggested statement for every remediable finding, each with a non-empty justification.

Forbidden: touching graph or detection logic, writing UI code, changing what counts as a "finding."

---

### PERSON 4 — Interactive Dashboard & Visualization
**You are the face of the demo. Build the UI shell immediately against dummy/mock JSON matching Sections 2.1–2.3 — do not wait for the other 3 to finish.**

Scope:
- Interactive graph visualization (D3.js or Cytoscape.js) rendering `graph_export.json`'s nodes/edges, color-coded by risk (pull risk scores from `findings.json` by matching path nodes to `finding.path`).
- Risk scorecards: a ranked list/table of findings from `findings.json`, showing `pattern_name`, `risk_score`, and the decomposed `risk_breakdown` (reachability / blast radius / exploit triviality) so the score is explainable on screen, not just a number.
- Click-to-expand: clicking a finding shows its `narrative` (plain-English attack story) and, if available, the corresponding entry from `remediations.json` with a "download fixed policy" action.
- Must run in static-file mode (reads the three JSON files from disk) as the required baseline — see Section 2.4.

Definition of Done: loading the dashboard against the three sample JSON files (even if hand-mocked, before real integration) renders the graph, the scorecards, and at least one working click-to-expand narrative + remediation view.

Forbidden: implementing any detection, scoring, or remediation logic yourself — if a number or narrative is wrong, that's Person 2 or 3's bug to fix, not something to patch client-side with your own guess.

---

## 4. Folder Structure (mandatory, everyone matches this exactly)

```
/repo-root
  /parser_graph/          ← Person 1 only
    README.md
    ...
  /detection_engine/      ← Person 2 only
    README.md
    rules/
    ...
  /remediation_generator/ ← Person 3 only
    README.md
    ...
  /dashboard_ui/          ← Person 4 only
    README.md
    ...
  /schemas/                ← shared, edit only with group sign-off
    graph_export.schema.json
    findings.schema.json
    remediations.schema.json
  /sample_data/            ← shared, Person 1 delivers first version
    iam_export_sample.json
  main.py / app.py         ← shared orchestrator, Integrator-owned
  requirements.txt         ← shared, announce before editing
  README.md                ← project-level, Integrator-owned
```

Each module `README.md` template (fill this in, don't skip it):
```
## What this module does
## How to run it standalone
## Input file(s) expected and where
## Output file produced and where
## Known limitations / things not implemented
```

---

## 5. Integration Plan — "Stitching It Together"

Designate ONE person as **Integrator** (suggest: whoever is most comfortable with git — does not have to be Person 1, but Person 1's schema knowledge helps). The Integrator's job, and ONLY the Integrator's job:
1. Reviews each Pull Request against that person's Definition of Done and the schema contract.
2. Merges PRs into `main` in dependency order: Person 1 → Person 2 → Person 3 → Person 4.
3. Runs the full pipeline end-to-end on `main` after each merge to confirm nothing broke.
4. Owns `main.py`/`app.py` — the thin orchestrator script that calls each module in sequence and passes files between them. No individual module should hardcode calls to another module's internals; they only agree via the JSON files in Section 2.

Nobody merges into `main` except the Integrator. If the Integrator is unavailable, work continues on individual branches — do not merge to unblock yourself, wait or escalate in the group chat.

---

## 6. Dependency Chain & Deadlines (fill in actual dates/times for your hackathon clock)

| Milestone | Owner | Depends on | Deadline |
|---|---|---|---|
| `sample_data/iam_export_sample.json` delivered | Person 1 | — | **T+0 (earliest possible)** |
| `graph_export.json` (schema-valid) from real parser | Person 1 | sample data | T+X |
| `findings.json` (schema-valid, catches embedded chains) | Person 2 | graph_export.json | T+X+Y |
| `remediations.json` (schema-valid) | Person 3 | findings.json (can start with stub earlier) | T+X+Y+Z |
| Dashboard renders real (non-stub) data end-to-end | Person 4 | all of the above | T+X+Y+Z+W |
| Integrator: full pipeline runs on `main` via `app.py` | Integrator | all merges done | Final integration checkpoint |
| Deck / video / ZIP packaging | Whole team | working pipeline | Submission deadline |

Fill in T+X/Y/Z/W with your actual hackathon hours before you start — this table is the thing that prevents "I was waiting on you" arguments on the last day.

---

## 7. Deliverables Checklist (map back to the problem statement)

- [ ] Source Code ZIP: full repo, `main` branch, with all 4 modules integrated and `app.py` runnable end-to-end on the sample data.
- [ ] Presentation Deck (.pptx/.pdf): must cover — problem framing (graph reachability, not checklist), architecture diagram (Section 1's pipeline), the 3-factor risk score formula (explainable, not black-box), the detect→explain→auto-fix closed loop as the headline differentiator, and an honest "what's stretch/roadmap vs. built" slide.
- [ ] Video Demo (3–5 min): show the sample data's embedded escalation chain being detected, its plain-English narrative, its auto-generated least-privilege fix, and the interactive graph/scorecard — in that order, so it tells the "detect → explain → auto-fix" story live.

---

## 8. Strictness Summary (the non-negotiables, restated so nobody can claim they missed it)

1. Stay inside your folder. Always.
2. Match the JSON contract exactly. Always.
3. Push to your own branch only. Never to `main` directly.
4. Announce before touching any shared file.
5. Deliver your Definition-of-Done artifact by your deadline — the pipeline is only as fast as its slowest stage.
6. If blocked, build against a stub matching the schema and keep moving — never sit idle waiting for another person's module to be "finished" before you start.
7. If you disagree with something in this document, raise it with the group and get Section-2 sign-off before diverging — do not quietly build something different.
