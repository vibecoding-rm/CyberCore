import asyncio
import os
from uuid import uuid4

import psycopg
import pytest

from app.core.approvals import ApprovalService
from app.storage.postgres_approvals import PostgresApprovalRepository


DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


def service():
    return ApprovalService(PostgresApprovalRepository(DATABASE_URL))


@pytest.mark.asyncio
async def test_approval_consumption_is_atomic_and_single_use():
    approvals = service()
    issued = await approvals.issue(
        requested_by="integration-operator",
        approved_by="integration-approver",
        tool_name="approval_probe",
        normalized_arguments={"target": "192.168.10.25"},
        arguments_sha256="a" * 64,
        ttl_seconds=600,
    )
    first_request = uuid4()
    second_request = uuid4()

    try:
        results = await asyncio.gather(
            approvals.consume(
                issued.approval_token,
                "integration-operator",
                "approval_probe",
                "a" * 64,
                first_request,
            ),
            approvals.consume(
                issued.approval_token,
                "integration-operator",
                "approval_probe",
                "a" * 64,
                second_request,
            ),
        )

        assert sorted(results) == [False, True]
        async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
            row = await (
                await connection.execute(
                    """
                    SELECT
                        token_sha256,
                        requested_by,
                        approved_by,
                        tool_name,
                        normalized_arguments,
                        arguments_sha256,
                        consumed_at,
                        consumed_by_request_id
                    FROM approvals WHERE id = %s
                    """,
                    (issued.approval_id,),
                )
            ).fetchone()
        assert row[0].strip() == approvals.hash_token(issued.approval_token)
        assert row[0].strip() != issued.approval_token
        assert row[1] == "integration-operator"
        assert row[2] == "integration-approver"
        assert row[3] == "approval_probe"
        assert row[4] == {"target": "192.168.10.25"}
        assert row[5].strip() == "a" * 64
        assert row[6] is not None
        assert row[7] in {first_request, second_request}
    finally:
        await cleanup(issued.approval_id)


@pytest.mark.asyncio
async def test_approval_is_bound_to_actor_tool_arguments_and_expiration():
    approvals = service()
    issued = await approvals.issue(
        requested_by="integration-operator",
        approved_by="integration-approver",
        tool_name="approval_probe",
        normalized_arguments={"target": "192.168.10.25"},
        arguments_sha256="b" * 64,
        ttl_seconds=600,
    )

    try:
        assert not await approvals.consume(
            issued.approval_token,
            "different-operator",
            "approval_probe",
            "b" * 64,
            uuid4(),
        )
        assert not await approvals.consume(
            issued.approval_token,
            "integration-operator",
            "different_tool",
            "b" * 64,
            uuid4(),
        )
        assert not await approvals.consume(
            issued.approval_token,
            "integration-operator",
            "approval_probe",
            "c" * 64,
            uuid4(),
        )

        async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
            await connection.execute(
                """
                UPDATE approvals
                SET created_at = now() - interval '2 hours',
                    expires_at = now() - interval '1 hour'
                WHERE id = %s
                """,
                (issued.approval_id,),
            )

        assert not await approvals.consume(
            issued.approval_token,
            "integration-operator",
            "approval_probe",
            "b" * 64,
            uuid4(),
        )
    finally:
        await cleanup(issued.approval_id)


async def cleanup(approval_id):
    if not DATABASE_URL:
        return
    async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
        await connection.execute("DELETE FROM approvals WHERE id = %s", (approval_id,))
