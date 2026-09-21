from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict, max_length=32)
    requested_by: str = Field(default="operator", min_length=1, max_length=200)
    approval_token: str | None = Field(default=None, min_length=1, max_length=500)


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    risk: Literal["low", "medium", "high", "critical"]
    approval_required: bool = False


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid4().hex[:12].upper()}")
    source: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target: str
    data: dict[str, Any]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ToolResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    status: Literal["completed", "denied", "approval_required", "failed"]
    decision: PolicyDecision
    evidence: Evidence | None = None
    error: str | None = None
