import os
from uuid import uuid4

import psycopg
import pytest

from app.api.models import Evidence, PolicyDecision
from app.core.audit import AuditStoreError, ExecutionStart
from app.storage.postgres_journal import PostgresExecutionJournal


DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


def execution_start(execution_id, status="running"):
    return ExecutionStart(
        execution_id=execution_id,
        requested_by="integration-test",
        tool_name="get_mock_inventory",
        original_arguments={"target": "192.168.10.25"},
        normalized_arguments={"target": "192.168.10.25"},
        policy_decision=PolicyDecision(
            allowed=True,
            reason="integration test",
            risk="low",
        ),
        status=status,
    )


@pytest.mark.asyncio
async def test_completed_execution_and_evidence_are_durable():
    execution_id = uuid4()
    journal = PostgresExecutionJournal(DATABASE_URL)
    evidence = Evidence(
        source="get_mock_inventory",
        target="192.168.10.25",
        data={"source": "simulated", "target": "192.168.10.25"},
        sha256="a" * 64,
    )

    try:
        await journal.begin(execution_start(execution_id))
        await journal.finish(execution_id, "completed", evidence=evidence)

        async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
            execution_row = await (
                await connection.execute(
                    """
                    SELECT status, original_arguments, normalized_arguments, completed_at
                    FROM executions WHERE id = %s
                    """,
                    (execution_id,),
                )
            ).fetchone()
            evidence_row = await (
                await connection.execute(
                    "SELECT execution_id, sha256, raw_data FROM evidence WHERE id = %s",
                    (evidence.evidence_id,),
                )
            ).fetchone()

        assert execution_row[0] == "completed"
        assert execution_row[1] == {"target": "192.168.10.25"}
        assert execution_row[2] == {"target": "192.168.10.25"}
        assert execution_row[3] is not None
        assert evidence_row[0] == execution_id
        assert evidence_row[1].strip() == "a" * 64
        assert evidence_row[2]["source"] == "simulated"
    finally:
        await cleanup(execution_id)


@pytest.mark.asyncio
async def test_evidence_failure_rolls_back_terminal_status():
    first_id = uuid4()
    second_id = uuid4()
    journal = PostgresExecutionJournal(DATABASE_URL)
    duplicate_evidence_id = f"EVD-{uuid4().hex[:12].upper()}"
    first_evidence = Evidence(
        evidence_id=duplicate_evidence_id,
        source="get_mock_inventory",
        target="192.168.10.25",
        data={"attempt": 1},
        sha256="b" * 64,
    )
    second_evidence = Evidence(
        evidence_id=duplicate_evidence_id,
        source="get_mock_inventory",
        target="192.168.10.25",
        data={"attempt": 2},
        sha256="c" * 64,
    )

    try:
        await journal.begin(execution_start(first_id))
        await journal.finish(first_id, "completed", evidence=first_evidence)
        await journal.begin(execution_start(second_id))

        with pytest.raises(AuditStoreError):
            await journal.finish(second_id, "completed", evidence=second_evidence)

        async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
            status_row = await (
                await connection.execute(
                    "SELECT status, completed_at FROM executions WHERE id = %s",
                    (second_id,),
                )
            ).fetchone()
            evidence_count = await (
                await connection.execute(
                    "SELECT count(*) FROM evidence WHERE execution_id = %s",
                    (second_id,),
                )
            ).fetchone()

        assert status_row == ("running", None)
        assert evidence_count[0] == 0
    finally:
        await cleanup(second_id)
        await cleanup(first_id)


async def cleanup(execution_id):
    if not DATABASE_URL:
        return
    async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
        # Evidence is append-only; test cleanup bypasses the triggers as the
        # superuser, which is the only role able to do so.
        await connection.execute("SET session_replication_role = replica")
        await connection.execute(
            "DELETE FROM evidence WHERE execution_id = %s", (execution_id,)
        )
        await connection.execute(
            "DELETE FROM executions WHERE id = %s", (execution_id,)
        )
