from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class ToolRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID = Field(default_factory=uuid4)
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict, max_length=32)
    approval_token: str | None = Field(default=None, min_length=1, max_length=500)


class ToolRequest(ToolRequestInput):
    requested_by: str = Field(min_length=1, max_length=100)


class ApprovalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requested_by: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-zA-Z0-9._-]+$",
    )
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict, max_length=32)
    expires_in_seconds: int = Field(default=900, ge=60, le=86400)


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: UUID
    approval_token: str
    requested_by: str
    approved_by: str
    tool: str
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: datetime


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

    request_id: UUID
    status: Literal["completed", "denied", "approval_required", "failed"]
    decision: PolicyDecision
    evidence: Evidence | None = None
    error: str | None = None
