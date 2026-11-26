"""Pydantic schemas for AGENT SHIELD API (compatible with Pydantic v1 and v2)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    role: str = Field(..., min_length=2, max_length=80)
    description: str = Field(..., min_length=2, max_length=500)
    system_instructions: str = Field(..., min_length=2, max_length=2000)
    available_tools: List[str] = Field(default_factory=list)
    initial_permissions: List[Dict[str, Any]] = Field(default_factory=list)


class AgentStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="active or inactive")


class PermissionUpsertRequest(BaseModel):
    agent_id: str
    resource: str
    action: str
    effect: str = "ALLOW"
    max_amount: Optional[float] = None
    requires_approval_above: Optional[float] = None


class GatewayToolRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    prompt_context: Optional[str] = None
    # Optional 0-23 UTC hour override for deterministic off-hours anomaly testing/demos
    simulated_hour: Optional[int] = Field(default=None, ge=0, le=23)
    # Note: Even if a caller supplies an untrusted agent_id in the body,
    # the gateway strictly ignores it and derives identity from X-Agent-Key.
    untrusted_agent_id: Optional[str] = None


class ApprovalDecisionRequest(BaseModel):
    reviewer: str = "admin"
    notes: Optional[str] = None


class ScenarioRunRequest(BaseModel):
    scenario_id: int = Field(..., ge=1, le=9)
    params: Dict[str, Any] = Field(default_factory=dict)
