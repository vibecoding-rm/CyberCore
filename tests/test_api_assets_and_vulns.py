from contextlib import asynccontextmanager
import os
import httpx
import pytest

from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.core.budgets import ConcurrencyLease
from app.main import app
from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository


OPERATOR_KEY = "operator-key-with-at-least-32-characters"
DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


def operator_authenticator():
    return ApiKeyAuthenticator(
        [
            ApiCredential(
                subject="test-operator",
                role="operator",
                key_sha256=ApiKeyAuthenticator.hash_api_key(OPERATOR_KEY),
            )
        ]
    )


@asynccontextmanager
async def api_client():
    async with app.router.lifespan_context(app):
        app.state.authenticator = operator_authenticator()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
        ) as client:
            yield client


async def test_assets_endpoints():
    async with api_client() as client:
        # First execute mock inventory to trigger asset recording
        resp_exec = await client.post(
            "/v1/tools/execute",
            json={
                "tool": "get_mock_inventory",
                "arguments": {"target": "192.168.10.25"},
            },
        )
        assert resp_exec.status_code == 200

        # Query /v1/assets
        resp_assets = await client.get("/v1/assets")
        assert resp_assets.status_code == 200
        assets = resp_assets.json()
        assert isinstance(assets, list)
        assert len(assets) >= 1

        # Query /v1/assets/192.168.10.25
        resp_single = await client.get("/v1/assets/192.168.10.25")
        assert resp_single.status_code == 200
        single = resp_single.json()
        assert "192.168.10.25" in str(single["addresses"])


async def test_vulnerability_endpoints_and_inventory_analysis():
    # Seed known CVE in database
    vuln_repo = PostgresVulnerabilityRepository(DATABASE_URL)
    await vuln_repo.upsert_vulnerability(
        vulnerability_id="CVE-2021-44228",
        source="cisa_kev",
        title="Log4Shell Vulnerability",
        cvss=10.0,
        epss=0.9752,
        kev=True,
    )

    async with api_client() as client:
        # Query /v1/vulnerabilities
        resp_list = await client.get("/v1/vulnerabilities")
        assert resp_list.status_code == 200
        vulns = resp_list.json()
        assert any(v["vulnerability_id"] == "CVE-2021-44228" for v in vulns)

        # Query /v1/vulnerabilities/CVE-2021-44228
        resp_get = await client.get("/v1/vulnerabilities/CVE-2021-44228")
        assert resp_get.status_code == 200
        item = resp_get.json()
        assert item["vulnerability_id"] == "CVE-2021-44228"
        assert item["kev"] is True
        assert item["cvss"] == 10.0

        # Analysis with vulnerability_id referencing Log4Shell
        resp_analysis = await client.post(
            "/v1/analysis/inventory",
            json={
                "target": "192.168.10.25",
                "vulnerability_id": "CVE-2021-44228",
            },
        )
        assert resp_analysis.status_code == 200
        analysis = resp_analysis.json()
        assert analysis["assessment"] is not None
        observations = analysis["assessment"]["observations"]
        # Must observe KEV and EPSS
        assert any("CISA KEV" in obs for obs in observations)
        assert any("EPSS" in obs for obs in observations)
        assert any("CVSS" in obs for obs in observations)
