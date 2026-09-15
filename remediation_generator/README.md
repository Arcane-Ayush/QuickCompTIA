# Person 3 — Least-Privilege Remediation Generator (`/remediation_generator/`)

## What this module does
Consumes detection findings and synthesizes precise, least-privilege replacement IAM policy statements:
- Replaces wildcard actions (`*` or `service:*`) with specific scoped CRUD actions necessary for legitimate operation.
- Replaces unrestricted resource wildcards (`Resource: "*"`) with narrowed ARN patterns and resource namespaces.
- Injects critical security condition keys (e.g. `iam:PassedToService`, `aws:MultiFactorAuthPresent`, `aws:SecureTransport`).
- Provides an explainable, single-sentence justification for every suggested fix.

## How to run it standalone
From repo root:
```bash
python -m remediation_generator.generator findings.json remediations.json
```

## Input file(s) expected and where
- `findings.json`: Strictly adhering to Section 2.2 schema from Person 2's Detection Engine.

## Output file produced and where
- `remediations.json`: Strictly adhering to Section 2.3 schema with `finding_id`, `original_statement`, `suggested_statement`, and `justification`.

## Known limitations / things not implemented
- Complex architectural trust cycles spanning more than 3 accounts require organizational boundary restructuring and are flagged as `remediable: false` with explanatory rationale.
