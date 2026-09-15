# Pull Request #3: Person 3 — Least-Privilege Remediation Generator

- **Branch**: `feature/remediation-generator` ➔ `main`
- **Owner**: Person 3
- **Status**: Merged
- **Reviewer**: Integrator

---

## 📋 Overview
Consumes detection findings from Person 2 and automatically synthesizes precise, least-privilege replacement IAM policy statements:
1. Replaces wildcards (`*` or `service:*`) with specific CRUD actions.
2. Replaces broad resource wildcards (`Resource: "*"`) with narrowed ARN patterns.
3. Injects security condition blocks (e.g. `iam:PassedToService: ec2.amazonaws.com`, `aws:MultiFactorAuthPresent: true`, `aws:SecureTransport: true`).
4. Generates a plain-English, single-sentence justification for every fix.

---

## 📦 Files Added / Modified
- `remediation_generator/generator.py`: Scoped policy statement synthesizer and justification author.
- `remediation_generator/__init__.py`: Package exports.
- `remediation_generator/README.md`: Standalone execution guide.
- `schemas/remediations.schema.json`: Formal JSON schema contract (Section 2.3).

---

## ⚙️ Key Technical Features
1. **PassRole Remediation**: Restricts role target ARN to `role/AppRole-*` and enforces `iam:PassedToService: ec2.amazonaws.com`.
2. **CreatePolicyVersion Remediation**: Scopes policy version editing strictly to `policy/dev/*` namespace.
3. **Cross-Account Remediation**: Restricts role target ARN to `role/ContractorScopedRole-*` and enforces MFA authentication.
4. **S3 Wildcard Remediation**: Scopes `s3:*` down to `s3:GetObject` on designated bucket with TLS condition (`aws:SecureTransport: true`).
5. **Complex Path Flagging**: Properly identifies architectural multi-hop trust boundaries as `remediable: false` with explanatory rationale.

---

## 🧪 Verification & Output
```bash
python -m remediation_generator.generator findings.json remediations.json
```
- **Output**: `remediations.json` (11 remediations generated).
- **Validation**: Schema passed.
