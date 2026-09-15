# Person 1 — Parser & Graph Builder (`/parser_graph/`)

## What this module does
Parses raw AWS `GetAccountAuthorizationDetails` JSON exports containing users, roles, groups, inline policies, and managed policies. It normalizes all statements into structured policy tuples, calculates effective administrator equivalency (`is_admin_equivalent`), and constructs a directed graph using NetworkX representing identity relationships, policy attachments, `sts:AssumeRole` trust relationships, and `iam:PassRole` permissions.

## How to run it standalone
From repo root:
```bash
python -m parser_graph.graph_builder sample_data/iam_export_sample.json graph_export.json
```

## Input file(s) expected and where
- `sample_data/iam_export_sample.json`: Standard AWS CLI `GetAccountAuthorizationDetails` output format containing `UserDetailList`, `RoleDetailList`, `GroupDetailList`, and `Policies`.

## Output file produced and where
- `graph_export.json`: Strictly adheres to Section 2.1 schema containing `accounts`, `nodes`, and `edges`.

## Embedded Escalation Chains in Sample Data
1. **PassRole + RunInstances Pivot**: `dev-alice` has `ec2:RunInstances` and `iam:PassRole` targeting `EC2AppRole`, which in turn has `iam:PassRole` targeting `AdminRole`.
2. **CreatePolicyVersion Self-Privesc**: `ops-bob` has `iam:CreatePolicyVersion` on attached policy `OpsPolicyVersionPrivesc`.
3. **Cross-Account Trust Pivot**: `contractor-carol` (Account 111111111111) is trusted by `CrossAccountDeployRole` (Account 222222222222), which can assume `OrgAdminRole`.
4. **SetDefaultPolicyVersion Pivot**: `qa-eve` can switch default version on `QAPolicyVersionSwitch` to an unmanaged administrator version.
5. **Wildcard Over-permission**: `analyst-dave` has `s3:*` on `*` without conditions.
6. **Benign Baselines**: `sec-frank` (SecurityAuditReadOnly) and `billing-grace` (BillingReadOnly).

## Known limitations / things not implemented
- SCP (Service Control Policies) evaluation is not included as it requires AWS Organizations export.
- Session policy intersection during dynamic assume-role calls is approximated via the role's maximum effective permissions.
