import pytest

from app.intelligence.ingestion import parse_cisa_kev_json, IngestionError
from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository


def test_vulnerability_repo_rejects_empty_id():
    repo = PostgresVulnerabilityRepository("postgresql://unused")
    with pytest.raises(ValueError, match="vulnerability_id"):
        import asyncio
        asyncio.run(repo.upsert_vulnerability("", source="test"))


def test_parse_cisa_kev_json_valid():
    raw_data = {
        "title": "CISA KEV",
        "vulnerabilities": [
            {
                "cveID": "cve-2023-12345",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "Test Vulnerability",
                "dateAdded": "2023-01-01",
                "shortDescription": "Test description",
                "cwes": ["CWE-79"],
            }
        ],
    }
    parsed = parse_cisa_kev_json(raw_data)
    assert len(parsed) == 1
    assert parsed[0]["cveID"] == "CVE-2023-12345"
    assert parsed[0]["vendorProject"] == "TestVendor"
    assert parsed[0]["cwes"] == ["CWE-79"]


def test_parse_cisa_kev_json_invalid():
    with pytest.raises(IngestionError, match="no contiene una lista"):
        parse_cisa_kev_json({"status": "error"})
