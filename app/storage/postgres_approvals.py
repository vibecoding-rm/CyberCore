from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from app.core.approvals import ApprovalGrant, ApprovalStoreError


class PostgresApprovalRepository:
    def __init__(self, database_url: str, connect_timeout_seconds: int = 3):
        if connect_timeout_seconds <= 0:
            raise ValueError("El timeout de conexión debe ser positivo")
        self.database_url = database_url
        self.connect_timeout_seconds = connect_timeout_seconds

    async def create(self, grant: ApprovalGrant) -> datetime:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    INSERT INTO approvals (
                        id,
                        token_sha256,
                        requested_by,
                        approved_by,
                        tool_name,
                        normalized_arguments,
                        arguments_sha256,
                        created_at,
                        expires_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        now(), now() + (%s * interval '1 second')
                    )
                    RETURNING expires_at
                    """,
                    (
                        grant.approval_id,
                        grant.token_sha256,
                        grant.requested_by,
                        grant.approved_by,
                        grant.tool_name,
                        Jsonb(grant.normalized_arguments),
                        grant.arguments_sha256,
                        grant.ttl_seconds,
                    ),
                )
                row = await cursor.fetchone()
                if row is None:
                    raise ApprovalStoreError("PostgreSQL no devolvió la aprobación")
                return row[0]
        except ApprovalStoreError:
            raise
        except Exception as exc:
            raise ApprovalStoreError("No se pudo persistir la aprobación") from exc

    async def consume(
        self,
        token_sha256: str,
        requested_by: str,
        tool_name: str,
        arguments_sha256: str,
        request_id: UUID,
    ) -> bool:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    UPDATE approvals
                    SET consumed_at = now(), consumed_by_request_id = %s
                    WHERE token_sha256 = %s
                      AND requested_by = %s
                      AND tool_name = %s
                      AND arguments_sha256 = %s
                      AND consumed_at IS NULL
                      AND expires_at > now()
                    RETURNING id
                    """,
                    (
                        request_id,
                        token_sha256,
                        requested_by,
                        tool_name,
                        arguments_sha256,
                    ),
                )
                return await cursor.fetchone() is not None
        except Exception as exc:
            raise ApprovalStoreError("No se pudo consumir la aprobación") from exc

    async def ping(self) -> None:
        try:
            async with await self._connect() as connection:
                await connection.execute("SELECT 1 FROM approvals LIMIT 0")
        except Exception as exc:
            raise ApprovalStoreError("El almacén de aprobaciones no está disponible") from exc

    async def _connect(self) -> psycopg.AsyncConnection[Any]:
        return await psycopg.AsyncConnection.connect(
            self.database_url,
            connect_timeout=self.connect_timeout_seconds,
        )
