import asyncio
import os
from uuid import uuid4

import psycopg
import pytest

from app.storage.postgres_budgets import PostgresBudgetCoordinator


DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


def coordinator(budget_key):
    return PostgresBudgetCoordinator(
        DATABASE_URL,
        request_window_seconds=3600,
        lease_grace_seconds=1,
        budget_key=budget_key,
    )


@pytest.mark.asyncio
async def test_request_limit_is_atomic_across_concurrent_workers():
    budget_key = f"integration-{uuid4().hex}"
    budgets = coordinator(budget_key)

    try:
        results = await asyncio.gather(
            budgets.reserve_request(uuid4(), 1),
            budgets.reserve_request(uuid4(), 1),
        )

        assert sorted(results) == ["accepted", "limit_reached"]
    finally:
        await cleanup(budget_key)


@pytest.mark.asyncio
async def test_request_id_reservation_is_durable_and_single_use():
    budget_key = f"integration-{uuid4().hex}"
    budgets = coordinator(budget_key)
    request_id = uuid4()

    try:
        assert await budgets.reserve_request(request_id, 10) == "accepted"
        assert await budgets.reserve_request(request_id, 10) == "duplicate"
    finally:
        await cleanup(budget_key)


@pytest.mark.asyncio
async def test_expired_request_reservation_does_not_consume_window_capacity():
    budget_key = f"integration-{uuid4().hex}"
    budgets = coordinator(budget_key)

    try:
        assert await budgets.reserve_request(uuid4(), 1) == "accepted"
        async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
            await connection.execute(
                """
                UPDATE request_budget_reservations
                SET requested_at = now() - interval '2 hours'
                WHERE budget_key = %s
                """,
                (budget_key,),
            )

        assert await budgets.reserve_request(uuid4(), 1) == "accepted"
    finally:
        await cleanup(budget_key)


@pytest.mark.asyncio
async def test_concurrency_limit_is_atomic_and_reusable_after_release():
    budget_key = f"integration-{uuid4().hex}"
    budgets = coordinator(budget_key)
    first_request = uuid4()
    second_request = uuid4()

    try:
        leases = await asyncio.gather(
            budgets.acquire_slot(first_request, 1, 30),
            budgets.acquire_slot(second_request, 1, 30),
        )
        acquired = [lease for lease in leases if lease is not None]

        assert len(acquired) == 1
        await budgets.release_slot(acquired[0])
        waiting_request = (
            second_request
            if acquired[0].request_id == first_request
            else first_request
        )
        replacement = await budgets.acquire_slot(waiting_request, 1, 30)
        assert replacement is not None
        await budgets.release_slot(replacement)
    finally:
        await cleanup(budget_key)


@pytest.mark.asyncio
async def test_expired_concurrency_lease_is_recovered():
    budget_key = f"integration-{uuid4().hex}"
    budgets = coordinator(budget_key)

    try:
        expired = await budgets.acquire_slot(uuid4(), 1, 30)
        assert expired is not None
        async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
            await connection.execute(
                """
                UPDATE concurrency_leases
                SET acquired_at = now() - interval '2 hours',
                    expires_at = now() - interval '1 hour'
                WHERE budget_key = %s AND lease_id = %s
                """,
                (budget_key, expired.lease_id),
            )

        replacement = await budgets.acquire_slot(uuid4(), 1, 30)
        assert replacement is not None
        await budgets.release_slot(replacement)
    finally:
        await cleanup(budget_key)


async def cleanup(budget_key):
    if not DATABASE_URL:
        return
    async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
        await connection.execute(
            "DELETE FROM concurrency_leases WHERE budget_key = %s",
            (budget_key,),
        )
        await connection.execute(
            "DELETE FROM request_budget_reservations WHERE budget_key = %s",
            (budget_key,),
        )
