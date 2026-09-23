import os
from uuid import uuid4

import psycopg
import pytest

from app.intelligence.models import AffectedRange, NormalizedVulnerability
from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository

DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


def _range(criteria: str, **bounds: str) -> AffectedRange:
    return AffectedRange(
        match_kind="cpe",
        vendor="acme",
        product="widget",
        range_type="cpe",
        criteria=criteria,
        **bounds,
    )


def _cleanup(cve: str, record_ids: list[str]) -> None:
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("DELETE FROM vulnerabilities WHERE vulnerability_id = %s", (cve,))
        conn.execute(
            "DELETE FROM intel_source_records WHERE record_id = ANY(%s)", (record_ids,)
        )


@pytest.mark.asyncio
async def test_store_intel_record_keeps_provenance_and_replaces_per_record():
    repo = PostgresVulnerabilityRepository(DATABASE_URL)
    suffix = uuid4().int % 10**8
    cve = f"CVE-2099-{suffix:08d}"
    ghsa = f"GHSA-test-{suffix}"
    try:
        nvd = NormalizedVulnerability(
            vulnerability_id=cve,
            source="nvd",
            source_url="https://nvd.test",
            cvss=7.5,
            cvss_vector="CVSS:3.1/X",
            cwe_ids=["CWE-79"],
            ranges=[_range("nvd-a", version_end_excluding="2.0")],
        )
        first = await repo.store_intel_record(nvd, {"v": 1})
        again = await repo.store_intel_record(nvd, {"v": 1})
        assert first["source_record_id"] == again["source_record_id"]

        osv = NormalizedVulnerability(
            vulnerability_id=ghsa,
            source="osv",
            source_url="https://osv.test",
            aliases=[cve],
            ranges=[_range("osv-a", version_start_including="1.0")],
        )
        await repo.store_intel_record(osv, {"id": ghsa}, vulnerability_id=cve)

        # A new NVD revision replaces only NVD's own ranges.
        revised = nvd.model_copy(
            update={"ranges": [_range("nvd-b", version_end_excluding="3.0")]}
        )
        await repo.store_intel_record(revised, {"v": 2})

        ranges = await repo.get_affected_ranges(cve, vendor="acme", product="widget")
        assert sorted(r["criteria"] for r in ranges) == ["nvd-b", "osv-a"]
        assert all(len(r["source_sha256"]) == 64 for r in ranges)

        vuln = await repo.get_vulnerability(cve)
        assert vuln is not None
        assert vuln["cvss"] == 7.5 and vuln["cvss_vector"] == "CVSS:3.1/X"
        assert vuln["cwe_ids"] == ["CWE-79"]
        assert cve not in vuln["aliases"]

        with psycopg.connect(DATABASE_URL) as conn:
            count = conn.execute(
                "SELECT count(*) FROM intel_source_records WHERE record_id = %s", (cve,)
            ).fetchone()[0]
        assert count == 2  # both NVD revisions kept as evidence
    finally:
        _cleanup(cve, [cve, ghsa])
