from typing import Any
from uuid import UUID, uuid4

import psycopg

from app.core.budgets import (
    BudgetStoreError,
    ConcurrencyLease,
    RequestReservation,
)


class PostgresBudgetCoordinator:
    def __init__(
        self,
        database_url: str,
        connect_timeout_seconds: int = 3,
        request_window_seconds: int = 3600,
        lease_grace_seconds: int = 30,
        budget_key: str = "global",
    ):
        if connect_timeout_seconds <= 0:
            raise ValueError("El timeout de conexión debe ser positivo")
        if request_window_seconds <= 0:
            raise ValueError("La ventana de solicitudes debe ser positiva")
        if lease_grace_seconds < 0:
            raise ValueError("La gracia del lease no puede ser negativa")
        if not budget_key or len(budget_key) > 100:
            raise ValueError("La clave de presupuesto debe tener entre 1 y 100 caracteres")
        self.database_url = database_url
        self.connect_timeout_seconds = connect_timeout_seconds
        self.request_window_seconds = request_window_seconds
        self.lease_grace_seconds = lease_grace_seconds
        self.budget_key = budget_key

    async def reserve_request(
        self,
        request_id: UUID,
        max_requests: int,
    ) -> RequestReservation:
        if max_requests <= 0:
            raise ValueError("El límite de solicitudes debe ser positivo")
        try:
            async with await self._connect() as connection:
                async with connection.transaction():
                    await self._lock(
                        connection,
                        f"cybercore.request_budget:{self.budget_key}",
                    )
                    duplicate = await (
                        await connection.execute(
                            """
                            SELECT 1
                            FROM request_budget_reservations
                            WHERE budget_key = %s AND request_id = %s
                            UNION ALL
                            SELECT 1 FROM executions WHERE id = %s
                            LIMIT 1
                            """,
                            (self.budget_key, request_id, request_id),
                        )
                    ).fetchone()
                    if duplicate is not None:
                        return "duplicate"

                    count_row = await (
                        await connection.execute(
                            """
                            SELECT count(*)
                            FROM request_budget_reservations
                            WHERE budget_key = %s
                              AND requested_at > now() - (%s * interval '1 second')
                            """,
                            (self.budget_key, self.request_window_seconds),
                        )
                    ).fetchone()
                    if count_row is None:
                        raise BudgetStoreError("PostgreSQL no devolvió el presupuesto")
                    if count_row[0] >= max_requests:
                        return "limit_reached"

                    await connection.execute(
                        """
                        INSERT INTO request_budget_reservations (
                            budget_key,
                            request_id,
                            requested_at
                        ) VALUES (%s, %s, now())
                        """,
                        (self.budget_key, request_id),
                    )
                    return "accepted"
        except BudgetStoreError:
            raise
        except Exception as exc:
            raise BudgetStoreError(
                "No se pudo reservar el presupuesto de solicitudes"
            ) from exc

    async def acquire_slot(
        self,
        request_id: UUID,
        max_parallel: int,
        execution_timeout_seconds: float,
    ) -> ConcurrencyLease | None:
        if max_parallel <= 0:
            raise ValueError("El límite de concurrencia debe ser positivo")
        if execution_timeout_seconds <= 0:
            raise ValueError("La duración del lease debe ser positiva")

        lease = ConcurrencyLease(lease_id=uuid4(), request_id=request_id)
        lease_seconds = execution_timeout_seconds + self.lease_grace_seconds
        try:
            async with await self._connect() as connection:
                async with connection.transaction():
                    await self._lock(
                        connection,
                        f"cybercore.concurrency_budget:{self.budget_key}",
                    )
                    await connection.execute(
                        """
                        DELETE FROM concurrency_leases
                        WHERE budget_key = %s AND expires_at <= now()
                        """,
                        (self.budget_key,),
                    )
                    count_row = await (
                        await connection.execute(
                            """
                            SELECT count(*)
                            FROM concurrency_leases
                            WHERE budget_key = %s
                            """,
                            (self.budget_key,),
                        )
                    ).fetchone()
                    if count_row is None:
                        raise BudgetStoreError("PostgreSQL no devolvió la concurrencia")
                    if count_row[0] >= max_parallel:
                        return None

                    await connection.execute(
                        """
                        INSERT INTO concurrency_leases (
                            budget_key,
                            lease_id,
                            request_id,
                            acquired_at,
                            expires_at
                        ) VALUES (
                            %s, %s, %s, now(),
                            now() + (%s * interval '1 second')
                        )
                        """,
                        (
                            self.budget_key,
                            lease.lease_id,
                            lease.request_id,
                            lease_seconds,
                        ),
                    )
                    return lease
        except BudgetStoreError:
            raise
        except Exception as exc:
            raise BudgetStoreError("No se pudo adquirir capacidad de ejecución") from exc

    async def release_slot(self, lease: ConcurrencyLease) -> None:
        try:
            async with await self._connect() as connection:
                await connection.execute(
                    """
                    DELETE FROM concurrency_leases
                    WHERE budget_key = %s AND lease_id = %s
                    """,
                    (self.budget_key, lease.lease_id),
                )
        except Exception as exc:
            raise BudgetStoreError("No se pudo liberar capacidad de ejecución") from exc

    async def ping(self) -> None:
        try:
            async with await self._connect() as connection:
                await connection.execute(
                    """
                    SELECT
                        EXISTS (SELECT 1 FROM request_budget_reservations LIMIT 1),
                        EXISTS (SELECT 1 FROM concurrency_leases LIMIT 1)
                    """
                )
        except Exception as exc:
            raise BudgetStoreError("El coordinador de presupuestos no está disponible") from exc

    async def _connect(self) -> psycopg.AsyncConnection[Any]:
        return await psycopg.AsyncConnection.connect(
            self.database_url,
            connect_timeout=self.connect_timeout_seconds,
        )

    @staticmethod
    async def _lock(connection, lock_name: str) -> None:
        await connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (lock_name,),
        )
