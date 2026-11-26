"""
AGENT SHIELD - Pydantic Schemas
Request/Response validation models.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List
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


# ── Agent Schemas ──────────────────────────────────────────────────────────

class AgentCreate(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    agent_name: str = Field(..., min_length=2, max_length=128)
    agent_type: str = Field(..., min_length=2, max_length=64)
    description: Optional[str] = Field(None, max_length=512)
    status: AgentStatus = AgentStatus.ACTIVE
    resources: List[str] = Field(default_factory=list)
    actions: List[ActionType] = Field(default_factory=list)

    @validator('resources', each_item=True)
    def validate_resource(cls, v):
        if not v or not v.strip():
            raise ValueError("Resource name cannot be empty")
        if len(v) > 128:
            raise ValueError("Resource name too long")
        return v.strip().lower()

    @validator('agent_name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError("Agent name cannot be empty")
        return v.strip()


class AgentUpdate(BaseModel):
    agent_name: Optional[str] = Field(None, min_length=2, max_length=128)
    agent_type: Optional[str] = Field(None, min_length=2, max_length=64)
    description: Optional[str] = Field(None, max_length=512)
    status: Optional[AgentStatus] = None
    resources: Optional[List[str]] = None
    actions: Optional[List[ActionType]] = None


class AgentResponse(BaseModel):
    agent_id: str
    agent_name: str
    agent_type: str
    status: str
    description: Optional[str]
    created_at: str
    updated_at: str
    resources: List[str] = []
    actions: List[str] = []


# ── Authorization Schemas ──────────────────────────────────────────────────

class AuthorizationRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=64)
    resource: str = Field(..., min_length=1, max_length=128)
    action: ActionType
    metadata: Optional[dict] = None

    @validator('resource')
    def validate_resource(cls, v):
        if not v.strip():
            raise ValueError("Resource cannot be empty")
        return v.strip().lower()

    @validator('agent_id')
    def validate_agent_id(cls, v):
        if not v.strip():
            raise ValueError("Agent ID cannot be empty")
        return v.strip()


class AuthorizationResponse(BaseModel):
    decision: DecisionType
    agent_id: str
    agent_name: str
    resource: str
    action: str
    timestamp: str
    explanation: str
    denial_reason: Optional[str] = None
    anomaly_classification: Optional[str] = None
    anomaly_score: Optional[float] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_factors: Optional[List[str]] = None
    suggested_action: Optional[str] = None
    event_id: Optional[str] = None


# ── Anomaly Detection Schemas ──────────────────────────────────────────────

class ActivityData(BaseModel):
    agent_id: str
    requests_per_minute: float = Field(..., ge=0, le=10000)
    resources_accessed: int = Field(..., ge=0, le=1000)
    failed_attempts: int = Field(..., ge=0, le=10000)
    access_frequency: float = Field(..., ge=0, le=10000)
    unique_resources: int = Field(..., ge=0, le=500)
    off_hours_requests: int = Field(0, ge=0, le=10000)
    sensitive_resource_access: int = Field(0, ge=0, le=1000)


class AnomalyResponse(BaseModel):
    agent_id: str
    classification: str
    anomaly_score: float
    explanation: str
    features_used: dict


# ── Risk Score Schemas ──────────────────────────────────────────────────────

class RiskAssessmentRequest(BaseModel):
    agent_id: str
    recent_denied: int = Field(0, ge=0)
    total_requests: int = Field(0, ge=0)
    anomaly_score: Optional[float] = None
    is_anomalous: bool = False
    sensitive_access_count: int = Field(0, ge=0)
    privilege_escalation: bool = False
    high_frequency: bool = False


class RiskAssessmentResponse(BaseModel):
    agent_id: str
    risk_score: int
    risk_level: str
    contributing_factors: List[str]
    explanation: str
    suggested_action: str


# ── Audit Log Schemas ──────────────────────────────────────────────────────

class AuditLogFilter(BaseModel):
    agent_id: Optional[str] = None
    decision: Optional[str] = None
    risk_level: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


# ── Simulation Schemas ──────────────────────────────────────────────────────

class SimulationRequest(BaseModel):
    scenario: str
    agent_id: str
    resource: str
    action: ActionType
    repeat_count: int = Field(1, ge=1, le=50)
    metadata: Optional[dict] = None


# ── Alert Schemas ──────────────────────────────────────────────────────────

class AlertCreate(BaseModel):
    agent_id: str
    agent_name: str
    alert_type: str
    severity: str
    message: str
    details: Optional[str] = None
