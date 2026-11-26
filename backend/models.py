"""
AGENT SHIELD - Domain Data Models
Defines core data structures and object representations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class AgentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class ActionType(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyClassification(str, Enum):
    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class Agent:
    agent_id: str
    agent_name: str
    agent_type: str
    status: AgentStatus = AgentStatus.ACTIVE
    description: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    resources: List[str] = field(default_factory=list)
    actions: List[ActionType] = field(default_factory=list)

    def is_active(self) -> bool:
        return self.status == AgentStatus.ACTIVE

    def has_permission(self, resource: str, action: str) -> bool:
        return (resource.lower() in [r.lower() for r in self.resources] and
                action.upper() in [a.value if isinstance(a, ActionType) else a for a in self.actions])


@dataclass
class Permission:
    permission_id: Optional[int]
    agent_id: str
    resource: str
    action: ActionType
    created_at: Optional[str] = None


@dataclass
class AuditLogEntry:
    event_id: str
    timestamp: str
    agent_id: str
    agent_name: str
    resource: str
    action: str
    decision: DecisionType
    denial_reason: Optional[str] = None
    anomaly_classification: Optional[str] = None
    anomaly_score: Optional[float] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_factors: List[str] = field(default_factory=list)
    suggested_action: Optional[str] = None
    request_metadata: Optional[Dict[str, Any]] = None


@dataclass
class SecurityAlert:
    alert_id: str
    timestamp: str
    agent_id: str
    agent_name: str
    alert_type: str
    severity: RiskLevel
    message: str
    details: Optional[Dict[str, Any]] = None
    is_acknowledged: bool = False


@dataclass
class TestCaseResult:
    test_id: str
    test_name: str
    test_scenario: str
    test_input: str
    expected_result: str
    actual_result: Optional[str] = None
    status: str = "PENDING"
    error_details: Optional[str] = None
    execution_time_ms: float = 0.0
    run_at: Optional[str] = None
