from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.api.models import Evidence
from app.storage.postgres_journal import PostgresExecutionJournal


def test_journal_rejects_non_positive_connect_timeout():
    with pytest.raises(ValueError, match="timeout de conexión"):
        PostgresExecutionJournal("postgresql://unused", connect_timeout_seconds=0)


@pytest.mark.asyncio
async def test_finish_rejects_running_status_without_connecting():
    journal = PostgresExecutionJournal("postgresql://unused")
    with pytest.raises(ValueError, match="estado terminal"):
        await journal.finish(uuid4(), "running")


@pytest.mark.asyncio
async def test_finish_requires_evidence_for_completed_status():
    journal = PostgresExecutionJournal("postgresql://unused")
    with pytest.raises(ValueError, match="requiere evidencia"):
        await journal.finish(uuid4(), "completed")


@pytest.mark.asyncio
async def test_finish_rejects_evidence_for_failed_status():
    journal = PostgresExecutionJournal("postgresql://unused")
    evidence = Evidence(
        evidence_id="EVD-TEST",
        source="test",
        target="127.0.0.1",
        data={"ok": False},
        sha256="0" * 64,
        collected_at=datetime.now(timezone.utc),
    )
    with pytest.raises(ValueError, match="Sólo una ejecución completada"):
        await journal.finish(uuid4(), "failed", evidence=evidence)
