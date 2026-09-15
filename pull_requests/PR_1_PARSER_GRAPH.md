# Pull Request #1: Person 1 — Parser & Graph Builder

- **Branch**: `feature/parser-graph` ➔ `main`
- **Owner**: Person 1
- **Status**: Merged
- **Reviewer**: Integrator

---

## 📋 Overview
Implements the core authorization parser and directed graph constructor for the IAM Misconfiguration Detector. Parses AWS `GetAccountAuthorizationDetails` exports, normalizes statements into structured policy tuples, evaluates administrator equivalence (`is_admin_equivalent`), and constructs a multi-account directed graph via NetworkX.

---

## 📦 Files Added / Modified
- `parser_graph/parser.py`: Statement normalizer and administrator equivalence engine.
- `parser_graph/graph_builder.py`: NetworkX graph constructor exporting `graph_export.json`.
- `parser_graph/__init__.py`: Package exports.
- `parser_graph/README.md`: Module standalone documentation.
- `sample_data/iam_export_sample.json`: Multi-account AWS IAM authorization dataset with 28 principals and embedded escalation paths.
- `schemas/graph_export.schema.json`: Formal JSON schema contract (Section 2.1).

---

## ⚙️ Key Technical Features
1. **Statement Normalization**: Normalizes all inline and managed policy statements into `(Effect, Principal, Action[], Resource[], Condition{})` tuples.
2. **Admin Equivalency Computation**: Pre-evaluates whether principals possess `AdministratorAccess` or wildcard action/resource allowances (`*:*`).
3. **Directed Multi-Account Graph**:
   - Nodes: Users, Roles, Groups, Policies, Resources across accounts `111111111111` and `222222222222`.
   - Edges: `policy_attachment`, `group_membership`, `sts:AssumeRole`, and `iam:PassRole`.
4. **Schema Compliance**: Fully validates against Section 2.1 schema specification.

---

## 🧪 Verification & Output
```bash
python -m parser_graph.graph_builder sample_data/iam_export_sample.json graph_export.json
```
- **Output**: `graph_export.json` (28 nodes, 31 edges, 2 accounts).
- **Validation**: Schema passed.
