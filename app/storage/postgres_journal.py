from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from app.api.models import Evidence
from app.core.audit import AuditStoreError, ExecutionStart, ExecutionStatus


class PostgresExecutionJournal:
    def __init__(self, database_url: str, connect_timeout_seconds: int = 3):
        if connect_timeout_seconds <= 0:
            raise ValueError("El timeout de conexión debe ser positivo")
        self.database_url = database_url
        self.connect_timeout_seconds = connect_timeout_seconds

    async def begin(self, execution: ExecutionStart) -> None:
        completed = execution.status != "running"
        try:
            async with await self._connect() as connection:
                await connection.execute(
                    """
                    INSERT INTO executions (
                        id,
                        requested_by,
                        tool_name,
                        original_arguments,
                        normalized_arguments,
                        policy_decision,
                        status,
                        started_at,
                        completed_at,
                        error
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, now(),
                        CASE WHEN %s THEN now() ELSE NULL END,
                        %s
                    )
                    """,
                    (
                        execution.execution_id,
                        execution.requested_by,
                        execution.tool_name,
                        Jsonb(execution.original_arguments),
                        self._jsonb_or_none(execution.normalized_arguments),
                        Jsonb(execution.policy_decision.model_dump(mode="json")),
                        execution.status,
                        completed,
                        execution.error,
                    ),
                )
        except Exception as exc:
            raise AuditStoreError("No se pudo iniciar el registro durable") from exc

    async def finish(
        self,
        execution_id: UUID,
        status: ExecutionStatus,
        evidence: Evidence | None = None,
        error: str | None = None,
    ) -> None:
        if status == "running":
            raise ValueError("finish requiere un estado terminal")
        if status == "completed" and evidence is None:
            raise ValueError("Una ejecución completada requiere evidencia")
        if status != "completed" and evidence is not None:
            raise ValueError("Sólo una ejecución completada puede guardar evidencia")

        try:
            async with await self._connect() as connection:
                async with connection.transaction():
                    cursor = await connection.execute(
                        """
                        UPDATE executions
                        SET status = %s, completed_at = now(), error = %s
                        WHERE id = %s AND status = 'running'
                        RETURNING id
                        """,
                        (status, error, execution_id),
                    )
                    if await cursor.fetchone() is None:
                        raise AuditStoreError(
                            "La ejecución no existe o ya tiene un estado terminal"
                        )

                    if evidence is not None:
                        await connection.execute(
                            """
                            INSERT INTO evidence (
                                id,
                                execution_id,
                                source,
                                target,
                                sha256,
                                raw_data,
                                collected_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                evidence.evidence_id,
                                execution_id,
                                evidence.source,
                                evidence.target,
                                evidence.sha256,
                                Jsonb(evidence.data),
                                evidence.collected_at,
                            ),
                        )
        except AuditStoreError:
            raise
        except Exception as exc:
            raise AuditStoreError("No se pudo cerrar el registro durable") from exc

    async def ping(self) -> None:
        try:
            async with await self._connect() as connection:
                await connection.execute("SELECT 1")
        except Exception as exc:
            raise AuditStoreError("PostgreSQL no está disponible") from exc

    async def _connect(self) -> psycopg.AsyncConnection[Any]:
        return await psycopg.AsyncConnection.connect(
            self.database_url,
            connect_timeout=self.connect_timeout_seconds,
        )

    @staticmethod
    def _jsonb_or_none(value: dict[str, Any] | None) -> Jsonb | None:
        return Jsonb(value) if value is not None else None
