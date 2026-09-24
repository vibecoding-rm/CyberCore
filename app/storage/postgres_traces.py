from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.agent.traces import (
    AgentTrace,
    TraceReview,
    TraceReviewInput,
    TraceStep,
    TraceStoreError,
    TraceSummary,
)


class TraceNotFoundError(LookupError):
    pass


class PostgresTraceRepository:
    def __init__(self, database_url: str, connect_timeout_seconds: int = 3):
        if connect_timeout_seconds <= 0:
            raise ValueError("El timeout de conexión debe ser positivo")
        self.database_url = database_url
        self.connect_timeout_seconds = connect_timeout_seconds

    async def save(self, trace: AgentTrace) -> None:
        try:
            async with await self._connect() as connection:
                async with connection.transaction():
                    await connection.execute(
                        """
                        INSERT INTO agent_runs (
                            id, requested_by, operator_intent, model, status,
                            final_report, response_schema, started_at, completed_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            trace.run_id,
                            trace.requested_by,
                            trace.operator_intent,
                            trace.model,
                            trace.status,
                            trace.final_report,
                            Jsonb(trace.response_schema),
                            trace.started_at,
                            trace.completed_at,
                        ),
                    )
                    for step in trace.steps:
                        await connection.execute(
                            """
                            INSERT INTO agent_steps (
                                run_id, step_number, messages, raw_output, error,
                                observation, execution_id, prompt_tokens, generated_tokens
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                trace.run_id,
                                step.step_number,
                                Jsonb(step.messages),
                                step.raw_output,
                                step.error,
                                step.observation,
                                step.execution_id,
                                step.prompt_tokens,
                                step.generated_tokens,
                            ),
                        )
        except Exception as exc:
            raise TraceStoreError("No se pudo guardar la traza del orquestador") from exc

    async def list_runs(self, limit: int = 50) -> list[TraceSummary]:
        if not 1 <= limit <= 500:
            raise ValueError("limit debe estar entre 1 y 500")
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    SELECT r.id AS run_id, r.requested_by, r.operator_intent, r.model,
                           r.status, r.started_at,
                           (SELECT count(*) FROM agent_steps s WHERE s.run_id = r.id)
                               AS step_count,
                           (SELECT v.verdict FROM agent_trace_reviews v
                            WHERE v.run_id = r.id
                            ORDER BY v.reviewed_at DESC, v.id DESC LIMIT 1)
                               AS latest_verdict
                    FROM agent_runs r
                    ORDER BY r.started_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = await cursor.fetchall()
        except Exception as exc:
            raise TraceStoreError("No se pudieron listar las trazas") from exc
        return [TraceSummary.model_validate(row) for row in rows]

    async def get(self, run_id: UUID) -> AgentTrace:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    "SELECT * FROM agent_runs WHERE id = %s", (run_id,)
                )
                run = await cursor.fetchone()
                if run is None:
                    raise TraceNotFoundError(str(run_id))
                cursor = await connection.execute(
                    "SELECT * FROM agent_steps WHERE run_id = %s ORDER BY step_number",
                    (run_id,),
                )
                steps = await cursor.fetchall()
        except TraceNotFoundError:
            raise
        except Exception as exc:
            raise TraceStoreError("No se pudo leer la traza") from exc
        return self._trace_from_rows(run, steps)

    async def add_review(
        self,
        run_id: UUID,
        reviewer: str,
        review: TraceReviewInput,
    ) -> TraceReview:
        trace = await self.get(run_id)
        if reviewer == trace.requested_by:
            raise ValueError("Quien lanzó la ejecución no puede revisar su propia traza")
        known_steps = {step.step_number for step in trace.steps}
        unknown = set(review.corrections) - known_steps
        if unknown:
            raise ValueError(f"Pasos corregidos inexistentes: {sorted(unknown)}")
        corrections = {
            str(step): action.model_dump(mode="json")
            for step, action in review.corrections.items()
        }
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    INSERT INTO agent_trace_reviews (run_id, reviewer, verdict, notes, corrections)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING reviewed_at
                    """,
                    (run_id, reviewer, review.verdict, review.notes, Jsonb(corrections)),
                )
                row = await cursor.fetchone()
        except Exception as exc:
            raise TraceStoreError("No se pudo guardar la revisión") from exc
        return TraceReview(
            **review.model_dump(), run_id=run_id, reviewer=reviewer, reviewed_at=row["reviewed_at"]
        )

    async def latest_review(self, run_id: UUID) -> TraceReview | None:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    SELECT run_id, reviewer, verdict, notes, corrections, reviewed_at
                    FROM agent_trace_reviews WHERE run_id = %s
                    ORDER BY reviewed_at DESC, id DESC LIMIT 1
                    """,
                    (run_id,),
                )
                row = await cursor.fetchone()
        except Exception as exc:
            raise TraceStoreError("No se pudo leer la revisión") from exc
        return TraceReview.model_validate(row) if row else None

    async def approved_run_ids(self) -> list[UUID]:
        """Runs whose latest review is an approval."""
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    SELECT run_id FROM (
                        SELECT DISTINCT ON (run_id) run_id, verdict
                        FROM agent_trace_reviews
                        ORDER BY run_id, reviewed_at DESC, id DESC
                    ) latest
                    WHERE verdict = 'approved'
                    """
                )
                rows = await cursor.fetchall()
        except Exception as exc:
            raise TraceStoreError("No se pudieron listar las trazas aprobadas") from exc
        return [row["run_id"] for row in rows]

    @staticmethod
    def _trace_from_rows(run: dict[str, Any], steps: list[dict[str, Any]]) -> AgentTrace:
        return AgentTrace(
            run_id=run["id"],
            requested_by=run["requested_by"],
            operator_intent=run["operator_intent"],
            model=run["model"],
            status=run["status"],
            final_report=run["final_report"],
            response_schema=run["response_schema"],
            started_at=run["started_at"],
            completed_at=run["completed_at"],
            steps=[
                TraceStep.model_validate({k: v for k, v in step.items() if k != "run_id"})
                for step in steps
            ],
        )

    async def _connect(self) -> psycopg.AsyncConnection:
        return await psycopg.AsyncConnection.connect(
            self.database_url,
            connect_timeout=self.connect_timeout_seconds,
            row_factory=dict_row,
        )
