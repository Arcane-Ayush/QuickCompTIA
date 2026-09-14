# parser_graph — Person 1: Parser & Graph Builder

## What this module does

Parses an AWS `GetAccountAuthorizationDetails`-style IAM JSON export and builds a
directed privilege graph using [NetworkX](https://networkx.org/). It then exports
the graph to `graph_export.json` matching the Section 2.1 schema contract.

**This is the foundation module.** The Detection Engine (Person 2) and Dashboard
(Person 4) both consume `graph_export.json` as their primary input.

**Does NOT perform any detection, risk scoring, or UI work** (those are Person 2/3/4's
domains — see the build protocol).

---

## How to run it standalone

```bash
# From the repo root:
pip install -r requirements.txt

# Default run (reads sample_data/iam_export_sample.json, writes graph_export.json):
python parser_graph/main.py

# Custom paths:
python parser_graph/main.py --input path/to/export.json --output path/to/graph_export.json

# Skip validation step:
python parser_graph/main.py --no-validate
```

---

## Input file(s) expected and where

| File | Location | Format |
|------|----------|--------|
| IAM export | `sample_data/iam_export_sample.json` (default) | `GetAccountAuthorizationDetails`-style JSON with `UserDetailList`, `RoleDetailList`, `GroupDetailList`, `Policies` keys |

The module accepts any file in this format, not just the sample. Point `--input` at a
real export if testing locally (never commit real AWS credentials or account data).

---

## Output file produced and where

| File | Default location | Schema |
|------|-----------------|--------|
| `graph_export.json` | repo root | `schemas/graph_export.schema.json` |

Schema-validated automatically at the end of each run. If validation fails, an error
is printed to stderr and the exit code is non-zero.

---

## Escalation chains embedded in `sample_data/iam_export_sample.json`

Person 2: these are the 3 chains your detector **must** catch. If any of them are
missing from your `findings.json`, that is a detection bug.

### Chain A — PassRole + RunInstances (credential theft)
- **Principal**: `arn:aws:iam::111111111111:user/dev-alice`
- **Mechanism**: `dev-alice` has `PassRolePolicy` attached, which grants `iam:PassRole`
  on `Resource: *` (wildcard). She is also in `dev-group`, which has `DevPolicy`
  granting `ec2:RunInstances`. She can therefore launch a new EC2 instance and pass it
  `EC2InstanceRole`, which has `AdminPolicy` (`Action: *, Resource: *`) attached.
  This gives her full admin access through the instance's instance profile.
- **Graph edges to look for**:
  - `dev-alice → arn:aws:iam::*:resource/wildcard` (`iam:PassRole`, `is_wildcard_resource=true`)
  - `dev-alice → dev-group` (`group_membership`)
  - `dev-group → DevPolicy` (`policy_attachment`)
  - `EC2InstanceRole → AdminPolicy` (`policy_attachment`)

### Chain B — CreatePolicyVersion self-privilege-escalation
- **Principal**: `arn:aws:iam::111111111111:user/ci-bot`
- **Mechanism**: `ci-bot` has `CreateVersionPolicy` attached, which grants
  `iam:CreatePolicyVersion` on `Resource: *`. This lets `ci-bot` create a new
  **default** version of **any** managed policy — including the policies attached to
  itself (`CIPolicy`) — replacing them with admin-granting content. This is a
  well-known Rhino Security Labs self-privesc path.
- **Graph edges to look for**:
  - `ci-bot → CreateVersionPolicy` (`policy_attachment`)
  - `CreateVersionPolicy` statements containing `iam:CreatePolicyVersion` on `*`

### Chain C — Cross-account trust pivot
- **Principal**: `arn:aws:iam::222222222222:user/external-auditor`
- **Mechanism**: `external-auditor` (account `222222222222`) has `CrossAccountPolicy`
  attached, which allows `sts:AssumeRole` on
  `arn:aws:iam::111111111111:role/CrossAccountRole`. That role's trust policy allows
  the root of account `222222222222` to assume it (with an ExternalId condition).
  `CrossAccountRole` has `AdminPolicy` attached — full admin in account `111111111111`.
- **Graph edges to look for**:
  - `external-auditor → CrossAccountPolicy` (`policy_attachment`)
  - `arn:aws:iam::222222222222:root → CrossAccountRole` (`sts:AssumeRole`,
    condition = `{"StringEquals": {"sts:ExternalId": "audit-ext-12345"}}`)
  - `CrossAccountRole → AdminPolicy` (`policy_attachment`)

---

## Known limitations / things not implemented

- **Service Control Policies (SCPs)**: not parsed — assume no SCP restrictions.
- **Permission Boundaries**: not parsed — assume no boundaries are set.
- **Resource-based policies** (e.g., S3 bucket policies, KMS key policies): not modeled
  — only identity-based (IAM) policies are in scope for this module.
- **Deny statements**: parsed and stored in normalized form but NOT used to subtract
  from Allow grants in `is_admin_equivalent` computation. Conservative (may produce
  false positives); Detection Engine should refine if needed.
- **Managed policies from AWS** (e.g., `arn:aws:iam::aws:policy/...`): only
  `AdministratorAccess` is recognized by name; other AWS-managed policies are not
  expanded (their document is not in the export). Mark as non-admin unless
  AdministratorAccess.

