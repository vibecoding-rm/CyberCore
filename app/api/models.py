from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class ToolRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    requested_by: str = "operator"
    approval_token: str | None = None


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    risk: Literal["low", "medium", "high", "critical"]
    approval_required: bool = False


class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid4().hex[:12].upper()}")
    source: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target: str
    data: dict[str, Any]
    sha256: str


class ToolResponse(BaseModel):
    request_id: str
    status: Literal["completed", "denied", "approval_required", "failed"]
    decision: PolicyDecision
    evidence: Evidence | None = None
    error: str | None = None
