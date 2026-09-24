"""Orchestrator traces: the exact model inputs and outputs of each run.

They are the raw material for Phase 6 (QLoRA). A trace only becomes a training
example after a human approver reviews it (see TraceReview); the export step
sanitizes it and never reads unreviewed runs.
"""

from datetime import datetime
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent.models import AgentThoughtAndAction


class TraceStoreError(RuntimeError):
    pass


class TraceStep(BaseModel):
    """One model call: what it received, what it emitted and what followed."""

    step_number: int = Field(ge=1)
    messages: list[dict[str, str]]
    raw_output: str | None = None
    error: str | None = None
    observation: str | None = None
    execution_id: UUID | None = None
    prompt_tokens: int | None = Field(default=None, ge=0)
    generated_tokens: int | None = Field(default=None, ge=0)


class AgentTrace(BaseModel):
    run_id: UUID
    requested_by: str
    operator_intent: str
    model: str
    status: str
    final_report: str
    response_schema: dict[str, Any]
    started_at: datetime
    completed_at: datetime
    steps: list[TraceStep]


TraceVerdict = Literal["approved", "rejected"]


class TraceReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: TraceVerdict
    notes: str = Field(default="", max_length=4000)
    # Step number -> the answer the model should have given. Only an approved
    # trace can carry corrections; a rejected one is simply never exported.
    corrections: dict[int, AgentThoughtAndAction] = Field(default_factory=dict)

    @model_validator(mode="after")
    def corrections_only_when_approved(self) -> "TraceReviewInput":
        if self.corrections and self.verdict != "approved":
            raise ValueError("Sólo una traza aprobada puede llevar correcciones")
        if any(step < 1 for step in self.corrections):
            raise ValueError("Los pasos corregidos empiezan en 1")
        return self


class TraceReview(TraceReviewInput):
    run_id: UUID
    reviewer: str
    reviewed_at: datetime


class TraceSummary(BaseModel):
    run_id: UUID
    requested_by: str
    operator_intent: str
    model: str
    status: str
    started_at: datetime
    step_count: int
    latest_verdict: TraceVerdict | None = None


class TraceRecorder(Protocol):
    async def save(self, trace: AgentTrace) -> None: ...
