import json

import httpx
import pytest
from pydantic import SecretStr

import app.main as main_module
from app.core.evidence_analysis import EvidenceGapAnalyzer
from app.integrations.defectdojo import (
    DefectDojoClient,
    DefectDojoError,
    DefectDojoSettings,
    build_generic_finding,
    dojo_test_title,
    severity_from_cvss,
)
from app.main import app
from tests.test_nuclei_validation import (
    CVE,
    FakeEvidenceStore,
    _match,
    api_client,
    inventory,
    nuclei_evidence,
)

TOKEN = "dojo-secret-token-0123456789"
SETTINGS = DefectDojoSettings(base_url="https://dojo.test", api_token=SecretStr(TOKEN))
VULN_INFO = {
    "cvss": 8.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe_ids": ["CWE-364"],
    "kev": False,
    "aliases": ["GHSA-xxxx", CVE],
}


async def assessment_for(validated: bool, simulated: bool = False):
    return EvidenceGapAnalyzer().analyze(
        inventory(simulated=simulated),
        CVE,
        version_matches=[await _match()],
        validation_evidence=[nuclei_evidence()] if validated else [],
    )


@pytest.mark.parametrize(
    ("cvss", "expected"),
    [(None, "Info"), (0.0, "Info"), (3.9, "Low"), (4.0, "Medium"), (7.0, "High"), (9.0, "Critical")],
)
def test_severity_bands(cvss, expected):
    assert severity_from_cvss(cvss) == expected


@pytest.mark.asyncio
async def test_confirmed_finding_is_verified_with_evidence_hashes():
    assessment = await assessment_for(validated=True)
    finding = build_generic_finding(assessment, inventory(), VULN_INFO)

    assert finding["verified"] is True and finding["active"] is True
    assert finding["severity"] == "High"
    assert finding["cwe"] == 364
    assert finding["cvssv3"].startswith("CVSS:3.1")
    assert finding["vulnerability_ids"] == ["GHSA-xxxx"]
    assert finding["unique_id_from_tool"] == f"cybercore:192.168.10.25:{CVE}"
    assert finding["endpoints"] == [{"host": "192.168.10.25"}]
    assert inventory().sha256 in finding["description"]
    assert "EVD-00000000000A" in finding["description"]
    assert "known_exploited" not in finding


@pytest.mark.asyncio
async def test_probable_is_exported_unverified_and_candidate_is_refused():
    probable = build_generic_finding(await assessment_for(validated=False), inventory(), VULN_INFO)
    assert probable["verified"] is False
    assert "independent_validation" in probable["description"]

    candidate = await assessment_for(validated=True, simulated=True)
    with pytest.raises(ValueError, match="probable o confirmed"):
        build_generic_finding(candidate, inventory(simulated=True), VULN_INFO)


@pytest.mark.asyncio
async def test_client_reimports_into_isolated_test_without_leaking_token():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers["authorization"]
        captured["body"] = request.content.decode("utf-8", errors="replace")
        return httpx.Response(201, json={"test_id": 42, "engagement_id": 7, "product_id": 3})

    http_client = httpx.AsyncClient(base_url="https://dojo.test", transport=httpx.MockTransport(handler))
    client = DefectDojoClient(SETTINGS, http_client=http_client)
    finding = {"title": "t", "severity": "High", "description": "d"}
    try:
        result = await client.reimport([finding], dojo_test_title("192.168.10.25", CVE))
    finally:
        await http_client.aclose()

    assert result["test_id"] == 42
    assert captured["auth"] == f"Token {TOKEN}"
    body = captured["body"]
    assert "Generic Findings Import" in body
    assert f"CyberCore 192.168.10.25 {CVE}" in body
    assert 'name="close_old_findings"\r\n\r\nfalse' in body
    assert json.dumps({"findings": [finding]}) in body


@pytest.mark.asyncio
async def test_client_errors_are_sanitized():
    def handler(_request):
        return httpx.Response(400, json={"detail": f"bad token {TOKEN}"})

    http_client = httpx.AsyncClient(base_url="https://dojo.test", transport=httpx.MockTransport(handler))
    client = DefectDojoClient(SETTINGS, http_client=http_client)
    try:
        with pytest.raises(DefectDojoError) as exc_info:
            await client.reimport([], "x")
    finally:
        await http_client.aclose()
    assert "HTTP 400" in str(exc_info.value) and TOKEN not in str(exc_info.value)
    assert TOKEN not in repr(SETTINGS)


class FakeDojoClient:
    calls: list = []

    def __init__(self, settings):
        self.settings = settings

    async def reimport(self, findings, test_title):
        FakeDojoClient.calls.append((findings, test_title))
        return {"test_id": 99, "engagement_id": 1, "product_id": 1, "statistics": None}

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_export_endpoint(monkeypatch):
    inv, val = inventory(), nuclei_evidence()
    store = FakeEvidenceStore({inv.evidence_id: inv, val.evidence_id: val})
    body = {
        "vulnerability_id": CVE,
        "inventory_evidence_id": inv.evidence_id,
        "validation_evidence_ids": [val.evidence_id],
    }
    monkeypatch.setattr(main_module, "DefectDojoClient", FakeDojoClient)
    FakeDojoClient.calls = []

    async with api_client(store) as client:
        app.state.defectdojo_settings = None
        dry = await client.post("/v1/findings/export", json={**body, "dry_run": True})
        unconfigured = await client.post("/v1/findings/export", json=body)
        app.state.defectdojo_settings = SETTINGS
        exported = await client.post("/v1/findings/export", json=body)
        injected = await client.post(
            "/v1/findings/export", json={**body, "finding": {"verified": True}}
        )

    assert dry.status_code == 200
    assert dry.json()["exported"] is False and dry.json()["finding"]["verified"] is True
    assert unconfigured.status_code == 503
    assert exported.status_code == 200 and exported.json()["defectdojo"]["test_id"] == 99
    assert FakeDojoClient.calls[0][1] == f"CyberCore 192.168.10.25 {CVE}"
    assert injected.status_code == 422  # the finding is always built server-side


@pytest.mark.asyncio
async def test_export_endpoint_refuses_candidates(monkeypatch):
    inv = inventory(simulated=True)
    store = FakeEvidenceStore({inv.evidence_id: inv})
    async with api_client(store) as client:
        response = await client.post(
            "/v1/findings/export",
            json={"vulnerability_id": CVE, "inventory_evidence_id": inv.evidence_id, "dry_run": True},
        )
    assert response.status_code == 422
