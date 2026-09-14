"""Generates plain-English attack narratives deterministically for IAM findings."""

from typing import List


def generate_known_pattern_narrative(
    template: str,
    source_name: str,
    target_name: str,
    hops: int,
    action: str,
) -> str:
    """Format deterministic narrative for a matched known privilege escalation pattern."""
    return template.format(
        source=source_name,
        target=target_name,
        hops=hops,
        action=action,
    )


def generate_novel_path_narrative(
    path: List[str],
    source_name: str,
    target_name: str,
    hop_labels: List[str],
) -> str:
    """Construct plain-English multi-hop lateral movement or escalation narrative."""
    hop_count = len(path) - 1
    if not hop_labels:
        return f"{source_name} can reach admin-equivalent target {target_name} in {hop_count} hop(s)."

    steps_str = ", then ".join(hop_labels)
    return (
        f"{source_name} can become admin in {hop_count} hop(s): {steps_str}."
    )


def generate_wildcard_narrative(
    principal_name: str,
    action: str,
    resource: str,
    policy_arn: str,
) -> str:
    """Generate risk narrative describing an excessive wildcard over-permission."""
    pol_name = policy_arn.split("/")[-1] if "/" in policy_arn else policy_arn
    return (
        f"{principal_name} is granted unrestricted permission '{action}' on '{resource}' "
        f"via policy {pol_name}, violating the principle of least privilege."
    )
