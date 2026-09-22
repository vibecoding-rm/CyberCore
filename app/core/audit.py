from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import UUID

from app.api.models import Evidence, PolicyDecision


ExecutionStatus = Literal[
    "running",
    "completed",
    "denied",
    "approval_required",
    "failed",
]


class AuditStoreError(RuntimeError):
    """Raised when a durable audit operation cannot be completed."""


@dataclass(frozen=True)
class ExecutionStart:
    execution_id: UUID
    requested_by: str
    tool_name: str
    original_arguments: dict[str, Any]
    normalized_arguments: dict[str, Any] | None
    policy_decision: PolicyDecision
    status: ExecutionStatus
    error: str | None = None


class ExecutionJournal(Protocol):
    async def begin(self, execution: ExecutionStart) -> None: ...

    async def finish(
        self,
        execution_id: UUID,
        status: ExecutionStatus,
        evidence: Evidence | None = None,
        error: str | None = None,
    ) -> None: ...
