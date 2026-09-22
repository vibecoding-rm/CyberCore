import os
from uuid import uuid4
import pytest

from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository


DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


@pytest.mark.asyncio
async def test_upsert_and_retrieve_vulnerability():
    repo = PostgresVulnerabilityRepository(DATABASE_URL)
    cve = f"CVE-TEST-{uuid4().hex[:8].upper()}"

    vid = await repo.upsert_vulnerability(
        vulnerability_id=cve,
        source="unit-test",
        title="Test RCE",
        description="A test vulnerability description",
        cvss=9.8,
        epss=0.85432,
        kev=True,
        cwe_ids=["CWE-89", "CWE-20"],
    )
    assert vid > 0

    record = await repo.get_vulnerability(cve)
    assert record is not None
    assert record["vulnerability_id"] == cve
    assert record["cvss"] == 9.8
    assert record["epss"] == 0.85432
    assert record["kev"] is True
    assert "CWE-89" in record["cwe_ids"]


@pytest.mark.asyncio
async def test_bulk_upsert_kev_and_epss():
    repo = PostgresVulnerabilityRepository(DATABASE_URL)
    cve1 = f"CVE-BULK1-{uuid4().hex[:6].upper()}"
    cve2 = f"CVE-BULK2-{uuid4().hex[:6].upper()}"

    kev_items = [
        {
            "cveID": cve1,
            "vulnerabilityName": "Bulk Test 1",
            "shortDescription": "Desc 1",
            "cwes": ["CWE-79"],
            "dateAdded": "2024-01-01",
        },
        {
            "cveID": cve2,
            "vulnerabilityName": "Bulk Test 2",
            "shortDescription": "Desc 2",
            "cwes": ["CWE-502"],
            "dateAdded": "2024-01-02",
        },
    ]

    kev_count = await repo.bulk_upsert_kev(kev_items)
    assert kev_count == 2

    # Now update EPSS for cve1
    epss_items = [{"cve": cve1, "epss": 0.45678}]
    epss_count = await repo.bulk_upsert_epss(epss_items)
    assert epss_count == 1

    rec1 = await repo.get_vulnerability(cve1)
    assert rec1 is not None
    assert rec1["kev"] is True
    assert rec1["epss"] == 0.45678
    assert rec1["title"] == "Bulk Test 1"

    rec2 = await repo.get_vulnerability(cve2)
    assert rec2 is not None
    assert rec2["kev"] is True
    assert rec2["epss"] is None
