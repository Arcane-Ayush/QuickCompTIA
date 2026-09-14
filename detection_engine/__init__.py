"""Detection Engine package for identifying IAM misconfigurations and privilege escalations."""

from detection_engine.detector import run_detection
from detection_engine.models import Finding, GraphEdge, GraphNode, OffendingStatement, RiskBreakdown
from detection_engine.path_finder import GraphPathFinder
from detection_engine.pattern_matcher import PatternMatcher
from detection_engine.risk_calculator import calculate_risk
from detection_engine.wildcard_scorer import WildcardScorer

__all__ = [
    "run_detection",
    "Finding",
    "GraphNode",
    "GraphEdge",
    "OffendingStatement",
    "RiskBreakdown",
    "PatternMatcher",
    "GraphPathFinder",
    "WildcardScorer",
    "calculate_risk",
]
