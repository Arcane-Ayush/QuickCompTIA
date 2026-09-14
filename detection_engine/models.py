"""Data models representing IAM graph objects and detection findings."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GraphNode:
    """Represents a principal, policy, or resource node in the IAM authorization graph."""

    id: str
    type: str
    account_id: str
    name: str
    attached_policies: List[str] = field(default_factory=list)
    is_admin_equivalent: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents a directed relationship or permission between IAM graph nodes."""

    source: str
    target: str
    permission: str
    condition: Optional[Dict[str, Any]] = None
    is_wildcard_resource: bool = False
    policy_arn: Optional[str] = None


@dataclass
class OffendingStatement:
    """Encapsulates the specific IAM policy statement responsible for a finding."""

    policy_arn: str
    action: str
    resource: str

    def to_dict(self) -> Dict[str, str]:
        """Convert the offending statement to a dictionary matching Section 2.2 contract."""
        return {
            "policy_arn": self.policy_arn,
            "action": self.action,
            "resource": self.resource,
        }


@dataclass
class RiskBreakdown:
    """Holds the explainable three-factor risk calculation parameters."""

    reachability: float
    blast_radius: float
    exploit_triviality: float

    def to_dict(self) -> Dict[str, float]:
        """Convert risk breakdown factors to a dictionary matching Section 2.2 contract."""
        return {
            "reachability": round(self.reachability, 4),
            "blast_radius": round(self.blast_radius, 4),
            "exploit_triviality": round(self.exploit_triviality, 4),
        }


@dataclass
class Finding:
    """Represents an identified security misconfiguration, privesc path, or wildcard grant."""

    finding_id: str
    type: str  # known_pattern | novel_path | wildcard_overpermission
    pattern_name: str
    path: List[str]
    risk_score: float
    risk_breakdown: RiskBreakdown
    narrative: str
    offending_statement: OffendingStatement

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding to dictionary strictly adhering to Section 2.2 contract."""
        return {
            "finding_id": self.finding_id,
            "type": self.type,
            "pattern_name": self.pattern_name,
            "path": self.path,
            "risk_score": round(self.risk_score, 1),
            "risk_breakdown": self.risk_breakdown.to_dict(),
            "narrative": self.narrative,
            "offending_statement": self.offending_statement.to_dict(),
        }
