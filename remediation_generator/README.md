# Person 3 — Least-Privilege Remediation Generator (`remediation_generator`)

## What this module does
The **Least-Privilege Remediation Generator** consumes IAM detection findings (`findings.json` from Person 2) and automatically generates minimal-privilege replacement policy statements with plain-English justifications (`remediations.json`). 

It employs a CRUD/ARN-scoped rule model to resolve:
1. **PassRole Over-permissions**: Scopes `iam:PassRole` resource ARNs to specific workload roles and adds `iam:PassedToService` conditions (e.g. `ec2.amazonaws.com`).
2. **Self-Privilege Escalation**: Restricts permission modification actions (`iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`) to scoped policy/role ARNs with conditions.
3. **Identity Self-Management**: Restricts credential actions (`iam:CreateAccessKey`, `iam:CreateLoginProfile`) strictly to `${aws:username}`.
4. **AssumeRole Scoping**: Narrows `sts:AssumeRole` targets and enforces ExternalId checks.
5. **Wildcard Action & Resource Trimming**: Converts `service:*` or `*:*` grants into specific CRUD actions and scoped resource ARNs.
6. **Usage-Grounded Trimming (Stretch Feature)**: Optional cross-checking against CloudTrail activity logs to strip un-utilized actions (Repokid-style).

---

## How to run it standalone

Run via CLI driver:
```bash
python -m remediation_generator.cli --input remediation_generator/sample_findings.json --output remediation_generator/remediations.json
```

Run unit tests:
```bash
python -m unittest remediation_generator/test_generator.py
```

Python library usage:
```python
from remediation_generator import RemediationGenerator

generator = RemediationGenerator()
remediations_data = generator.generate_remediations(findings_data)
```

---

## Input file(s) expected and where

- **Path**: `findings.json` (or passed via `--input`)
- **Schema (Section 2.2)**:
```json
{
  "findings": [
    {
      "finding_id": "F-001",
      "type": "known_pattern | novel_path | wildcard_overpermission",
      "pattern_name": "PassRole+RunInstances credential theft",
      "path": ["arn:aws:iam::111111111111:user/dev-alice", "arn:aws:iam::111111111111:role/AdminRole"],
      "risk_score": 87.5,
      "risk_breakdown": {"reachability": 0.9, "blast_radius": 0.95, "exploit_triviality": 0.85},
      "narrative": "dev-alice can become admin in 2 hops...",
      "offending_statement": {
        "policy_arn": "arn:aws:iam::111111111111:policy/DevPolicy",
        "action": "iam:PassRole",
        "resource": "*"
      }
    }
  ]
}
```

---

## Output file produced and where

- **Path**: `remediations.json` (or specified via `--output`)
- **Schema (Section 2.3)**:
```json
{
  "remediations": [
    {
      "finding_id": "F-001",
      "original_statement": {"action": "iam:PassRole", "resource": "*"},
      "suggested_statement": {
        "action": "iam:PassRole",
        "resource": "arn:aws:iam::111111111111:role/AdminRole",
        "condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
      },
      "justification": "Restricts PassRole to only the designated application role and enforces ec2.amazonaws.com target service, preventing arbitrary administrative role privilege escalation."
    }
  ]
}
```

---

## Known limitations / things not implemented
- Complex custom IAM condition logic requiring external IDP attributes (e.g. SAML/OIDC claim matching) requires custom rule extensions.
- Multi-account trust boundaries for novel paths flag `"remediable": false` for manual architectural review when no single policy statement can resolve the complex multi-hop path.
