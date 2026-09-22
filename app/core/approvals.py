import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID, uuid4


class ApprovalStoreError(RuntimeError):
    """Raised when a durable approval operation cannot be completed."""


@dataclass(frozen=True)
class ApprovalGrant:
    approval_id: UUID
    token_sha256: str
    requested_by: str
    approved_by: str
    tool_name: str
    normalized_arguments: dict[str, Any]
    arguments_sha256: str
    ttl_seconds: int


@dataclass(frozen=True)
class IssuedApproval:
    approval_id: UUID
    approval_token: str
    requested_by: str
    approved_by: str
    tool_name: str
    arguments_sha256: str
    expires_at: datetime


class ApprovalRepository(Protocol):
    async def create(self, grant: ApprovalGrant) -> datetime: ...

    async def consume(
        self,
        token_sha256: str,
        requested_by: str,
        tool_name: str,
        arguments_sha256: str,
        request_id: UUID,
    ) -> bool: ...

    async def ping(self) -> None: ...


class ApprovalService:
    def __init__(
        self,
        repository: ApprovalRepository,
        max_ttl_seconds: int = 3600,
    ):
        if max_ttl_seconds < 60:
            raise ValueError("El TTL máximo de aprobación debe ser de al menos 60 segundos")
        self.repository = repository
        self.max_ttl_seconds = max_ttl_seconds

    async def issue(
        self,
        requested_by: str,
        approved_by: str,
        tool_name: str,
        normalized_arguments: dict[str, Any],
        arguments_sha256: str,
        ttl_seconds: int,
    ) -> IssuedApproval:
        if requested_by == approved_by:
            raise ValueError("El aprobador no puede aprobar su propia ejecución")
        if not 60 <= ttl_seconds <= self.max_ttl_seconds:
            raise ValueError(
                f"La aprobación debe durar entre 60 y {self.max_ttl_seconds} segundos"
            )

        approval_token = secrets.token_urlsafe(32)
        grant = ApprovalGrant(
            approval_id=uuid4(),
            token_sha256=self.hash_token(approval_token),
            requested_by=requested_by,
            approved_by=approved_by,
            tool_name=tool_name,
            normalized_arguments=normalized_arguments,
            arguments_sha256=arguments_sha256,
            ttl_seconds=ttl_seconds,
        )
        expires_at = await self.repository.create(grant)
        return IssuedApproval(
            approval_id=grant.approval_id,
            approval_token=approval_token,
            requested_by=requested_by,
            approved_by=approved_by,
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
            expires_at=expires_at,
        )

    async def consume(
        self,
        token: str,
        requested_by: str,
        tool_name: str,
        arguments_sha256: str,
        request_id: UUID,
    ) -> bool:
        if not 32 <= len(token) <= 500:
            return False
        return await self.repository.consume(
            self.hash_token(token),
            requested_by,
            tool_name,
            arguments_sha256,
            request_id,
        )

    async def ping(self) -> None:
        await self.repository.ping()

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
