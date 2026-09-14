"""Risk score calculator evaluating reachability, blast radius, and exploit triviality."""

from typing import Optional, Tuple
from detection_engine.models import RiskBreakdown


def calculate_risk(
    reachability: float,
    blast_radius: float,
    exploit_triviality: float,
    condition_penalty: float = 0.0,
    hop_penalty: float = 0.0,
) -> Tuple[float, RiskBreakdown]:
    """Calculate composite risk score and return explainable 3-factor breakdown."""
    # Factor adjustments based on conditions and hop distance
    adjusted_reachability = max(0.1, min(1.0, reachability - hop_penalty))
    adjusted_triviality = max(0.1, min(1.0, exploit_triviality - condition_penalty))
    adjusted_blast = max(0.1, min(1.0, blast_radius))

    # Formula: Risk = Reachability * Blast_radius * Exploit_triviality * 100
    composite_score = adjusted_reachability * adjusted_blast * adjusted_triviality * 100.0
    composite_score = round(max(0.0, min(100.0, composite_score)), 1)

    breakdown = RiskBreakdown(
        reachability=round(adjusted_reachability, 4),
        blast_radius=round(adjusted_blast, 4),
        exploit_triviality=round(adjusted_triviality, 4),
    )
    return composite_score, breakdown


def evaluate_path_reachability(path_length: int) -> float:
    """Derive reachability score from graph path hop count."""
    if path_length <= 1:
        return 0.95
    # Decay slightly with each additional intermediate hop
    return max(0.4, 0.95 - (path_length - 1) * 0.1)


def evaluate_condition_complexity(condition: Optional[dict]) -> float:
    """Assess whether conditional constraints reduce exploit triviality."""
    if not condition:
        return 0.0
    # Any active conditional constraint makes exploitation non-trivial
    return 0.15
