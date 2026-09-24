import os
from datetime import datetime, timezone
from uuid import uuid4

import psycopg
import pytest

from app.agent.traces import AgentTrace, TraceReviewInput, TraceStep
from app.storage.postgres_traces import PostgresTraceRepository, TraceNotFoundError


DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


def sample_trace(requested_by: str = "trace-operator") -> AgentTrace:
    now = datetime.now(timezone.utc)
    return AgentTrace(
        run_id=uuid4(),
        requested_by=requested_by,
        operator_intent="Inventario de 192.168.10.25",
        model="mock-model",
        status="completed",
        final_report="Hecho.",
        response_schema={"type": "object"},
        started_at=now,
        completed_at=now,
        steps=[
            TraceStep(
                step_number=1,
                messages=[{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
                raw_output='{"thought":"t","action_type":"final_answer","final_summary":"Hecho."}',
                observation="El orquestador completó el análisis defensivo.",
                prompt_tokens=10,
                generated_tokens=5,
            )
        ],
    )


@pytest.mark.asyncio
async def test_trace_round_trip_and_review_lifecycle():
    repo = PostgresTraceRepository(DATABASE_URL)
    trace = sample_trace()
    await repo.save(trace)

    loaded = await repo.get(trace.run_id)
    assert loaded.steps[0].raw_output == trace.steps[0].raw_output
    assert loaded.steps[0].messages == trace.steps[0].messages
    assert await repo.latest_review(trace.run_id) is None
    assert trace.run_id not in await repo.approved_run_ids()

    correction = {"thought": "Mejor", "action_type": "final_answer", "final_summary": "Ok."}
    await repo.add_review(
        trace.run_id, "trace-reviewer", TraceReviewInput(verdict="approved", corrections={1: correction})
    )
    latest = await repo.latest_review(trace.run_id)
    assert latest.verdict == "approved"
    assert latest.corrections[1].thought == "Mejor"
    assert trace.run_id in await repo.approved_run_ids()

    # A later rejection wins over the earlier approval.
    await repo.add_review(trace.run_id, "trace-reviewer", TraceReviewInput(verdict="rejected"))
    assert trace.run_id not in await repo.approved_run_ids()
    summaries = {s.run_id: s for s in await repo.list_runs(500)}
    assert summaries[trace.run_id].latest_verdict == "rejected"
    assert summaries[trace.run_id].step_count == 1


@pytest.mark.asyncio
async def test_operator_cannot_review_own_trace_and_steps_must_exist():
    repo = PostgresTraceRepository(DATABASE_URL)
    trace = sample_trace(requested_by="same-person")
    await repo.save(trace)

    with pytest.raises(ValueError):
        await repo.add_review(trace.run_id, "same-person", TraceReviewInput(verdict="approved"))
    correction = {"thought": "t", "action_type": "final_answer", "final_summary": "s"}
    with pytest.raises(ValueError):
        await repo.add_review(
            trace.run_id, "other", TraceReviewInput(verdict="approved", corrections={7: correction})
        )
    with pytest.raises(TraceNotFoundError):
        await repo.get(uuid4())


@pytest.mark.asyncio
async def test_traces_and_reviews_are_append_only():
    repo = PostgresTraceRepository(DATABASE_URL)
    trace = sample_trace()
    await repo.save(trace)
    await repo.add_review(trace.run_id, "trace-reviewer", TraceReviewInput(verdict="approved"))

    for statement in (
        "UPDATE agent_runs SET status = 'x' WHERE id = %s",
        "DELETE FROM agent_steps WHERE run_id = %s",
        "UPDATE agent_trace_reviews SET verdict = 'rejected' WHERE run_id = %s",
    ):
        with psycopg.connect(DATABASE_URL) as connection:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(statement, (trace.run_id,))
