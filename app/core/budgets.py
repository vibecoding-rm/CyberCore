from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import UUID


RequestReservation = Literal["accepted", "limit_reached", "duplicate"]


class BudgetStoreError(RuntimeError):
    """Raised when shared request or concurrency budgets are unavailable."""


@dataclass(frozen=True)
class ConcurrencyLease:
    lease_id: UUID
    request_id: UUID


class BudgetCoordinator(Protocol):
    async def reserve_request(
        self,
        request_id: UUID,
        max_requests: int,
    ) -> RequestReservation: ...

    async def acquire_slot(
        self,
        request_id: UUID,
        max_parallel: int,
        execution_timeout_seconds: float,
    ) -> ConcurrencyLease | None: ...

    async def release_slot(self, lease: ConcurrencyLease) -> None: ...

    async def ping(self) -> None: ...
