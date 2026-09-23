import os
from uuid import uuid4

import psycopg
import pytest

from app.api.models import Evidence
from app.core.audit import EvidenceIntegrityError
from app.core.canonical import evidence_sha256
from app.storage.postgres_journal import PostgresExecutionJournal
from tests.integration.test_postgres_audit import cleanup, execution_start

DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


@pytest.mark.asyncio
async def test_get_evidence_verifies_sealed_hash_and_detects_tampering():
    execution_id = uuid4()
    journal = PostgresExecutionJournal(DATABASE_URL)
    data = {
        "target": "192.168.10.25",
        "findings": [{"template_id": "CVE-2024-6387", "cve_ids": ["CVE-2024-6387"]}],
        "score": 0.5,
        "nota": "evidencia con acentos: validación",
    }
    evidence = Evidence(
        source="run_nuclei_safe",
        target="192.168.10.25",
        data=data,
        sha256=evidence_sha256(data),
    )
    try:
        await journal.begin(execution_start(execution_id))
        assert await journal.get_evidence(evidence.evidence_id) is None  # still running

        await journal.finish(execution_id, "completed", evidence=evidence)
        loaded = await journal.get_evidence(evidence.evidence_id)
        assert loaded is not None
        assert loaded.data == data and loaded.sha256 == evidence.sha256

        async with await psycopg.AsyncConnection.connect(DATABASE_URL) as connection:
            await connection.execute(
                """
                UPDATE evidence
                SET raw_data = jsonb_set(raw_data, '{findings,0,cve_ids}', '["CVE-2021-44228"]')
                WHERE id = %s
                """,
                (evidence.evidence_id,),
            )
        with pytest.raises(EvidenceIntegrityError):
            await journal.get_evidence(evidence.evidence_id)
    finally:
        await cleanup(execution_id)
