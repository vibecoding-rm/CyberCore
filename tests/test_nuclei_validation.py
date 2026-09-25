from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

from app.api.models import Evidence, EvidenceCaseBundle
from app.core.audit import AuditStoreError, EvidenceIntegrityError
from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.core.canonical import evidence_sha256
from app.core.evidence_analysis import EvidenceGapAnalyzer, decide_status
from app.core.evidence_bundle import verify_evidence_case
from app.core.evidence_signing import EvidenceSigner
from app.core.validation import assess_nuclei_validation
from app.intelligence.matching import VulnerabilityMatcher
from app.main import app
from tests.test_matching import FakeRangeRepository, stored

CVE = "CVE-2024-6387"
TARGET = "192.168.10.25"
OPERATOR_KEY = "operator-key-with-at-least-32-characters"
SIGNER = EvidenceSigner.generate()


def nuclei_evidence(
    *,
    mode: str = "active",
    cve_ids: list[str] | None = None,
    target: str = TARGET,
    simulated: bool = False,
    source: str = "run_nuclei_safe",
    findings: bool = True,
    evidence_id: str = "EVD-00000000000A",
) -> Evidence:
    data: dict[str, Any] = {
        "target": target,
        "engine_version": "3.4.10",
        "templates": [{"id": CVE, "mode": mode, "sha256": "c" * 64, "path": "x.yaml"}],
        "findings": [
            {
                "template_id": CVE,
                "cve_ids": cve_ids if cve_ids is not None else [CVE],
                "matched_at": f"http://{target}:22",
            }
        ]
        if findings
        else [],
    }
    if simulated:
        data["source"] = "simulated"
    return Evidence(
        evidence_id=evidence_id, source=source, target=target, data=data, sha256=evidence_sha256(data)
    )


def inventory(simulated: bool = False, cpe: str = "cpe:/a:openbsd:openssh:9.6p1") -> Evidence:
    data: dict[str, Any] = {
        "services": [
            {"port": 22, "state": "open", "product": "OpenSSH", "version": "9.6p1", "cpe": cpe}
        ]
    }
    if simulated:
        data["source"] = "simulated"
    return Evidence(
        evidence_id="EVD-0000000000B1",
        source="inspect_services" if not simulated else "get_mock_inventory",
        target=TARGET,
        data=data,
        sha256=evidence_sha256(data),
    )


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"simulated": True, "range_state": "affected", "advisory_resolved": True, "validated": True}, "candidate"),
        ({"simulated": False, "range_state": "affected", "advisory_resolved": True, "validated": True}, "confirmed"),
        ({"simulated": False, "range_state": "affected", "advisory_resolved": False, "validated": True}, "probable"),
        ({"simulated": False, "range_state": "unresolved", "advisory_resolved": True, "validated": True}, "probable"),
        ({"simulated": False, "range_state": "not_affected", "advisory_resolved": True, "validated": True}, "candidate"),
        ({"simulated": False, "range_state": "affected", "advisory_resolved": True, "validated": False}, "probable"),
        ({"simulated": False, "range_state": "unresolved", "advisory_resolved": False, "validated": False}, "candidate"),
    ],
)
def test_decision_table(kwargs, expected):
    assert decide_status(**kwargs)[0] == expected


def test_contradiction_is_explained():
    status, conclusion = decide_status(
        simulated=False, range_state="not_affected", advisory_resolved=True, validated=True
    )
    assert status == "candidate" and "Contradicción" in conclusion


def test_active_hit_validates():
    result = assess_nuclei_validation([nuclei_evidence()], TARGET, CVE)
    assert result.status == "validated"
    assert result.evidence_ids == ["EVD-00000000000A"]
    assert "3.4.10" in result.observations[0]


@pytest.mark.parametrize(
    ("evidence", "fragment"),
    [
        (nuclei_evidence(mode="passive"), "pasiva"),
        (nuclei_evidence(simulated=True), "simulada"),
        (nuclei_evidence(target="192.168.10.99"), "no contra"),
        (nuclei_evidence(source="inspect_services"), "no procede"),
    ],
)
def test_non_qualifying_evidence_never_validates(evidence, fragment):
    result = assess_nuclei_validation([evidence], TARGET, CVE)
    assert result.status == "not_applicable"
    assert any(fragment in obs for obs in result.observations)


def test_finding_for_another_cve_does_not_validate():
    result = assess_nuclei_validation(
        [nuclei_evidence(cve_ids=["CVE-2021-41773"])], TARGET, CVE
    )
    assert result.status != "validated"


def test_silent_active_run_is_not_reproduced_not_false_positive():
    result = assess_nuclei_validation([nuclei_evidence(findings=False)], TARGET, CVE)
    assert result.status == "not_reproduced"
    assert "No prueba ausencia" in result.observations[0]


def test_no_cve_means_not_applicable():
    assert assess_nuclei_validation([nuclei_evidence()], TARGET, None).status == "not_applicable"


async def _match(cpe: str = "cpe:/a:openbsd:openssh:9.6p1"):
    return await VulnerabilityMatcher(FakeRangeRepository([stored()])).match_cpe(CVE, cpe)


@pytest.mark.asyncio
async def test_full_chain_confirms():
    assessment = EvidenceGapAnalyzer().analyze(
        inventory(),
        CVE,
        version_matches=[await _match()],
        validation_evidence=[nuclei_evidence()],
    )
    assert assessment.finding_status == "confirmed"
    assert assessment.outcome == "sufficient_evidence"
    assert assessment.can_confirm is True
    assert assessment.missing_evidence == []
    assert assessment.validation_evidence_ids == ["EVD-00000000000A"]


@pytest.mark.asyncio
async def test_simulated_inventory_never_confirms_even_with_validation():
    assessment = EvidenceGapAnalyzer().analyze(
        inventory(simulated=True),
        CVE,
        version_matches=[await _match()],
        validation_evidence=[nuclei_evidence()],
    )
    assert assessment.finding_status == "candidate"
    assert assessment.can_confirm is False
    assert "real_inventory" in {gap.code for gap in assessment.missing_evidence}


@pytest.mark.asyncio
async def test_validation_with_ambiguous_version_stays_probable():
    assessment = EvidenceGapAnalyzer().analyze(
        inventory(cpe="cpe:/a:openbsd:openssh:9.8p1"),
        CVE,
        version_matches=[await _match("cpe:/a:openbsd:openssh:9.8p1")],
        validation_evidence=[nuclei_evidence()],
    )
    codes = {gap.code for gap in assessment.missing_evidence}
    assert assessment.finding_status == "probable"
    assert "independent_validation" not in codes
    assert "affected_version_range" in codes


class FakeEvidenceStore:
    def __init__(self, items: dict[str, Evidence], broken: set[str] | None = None):
        self.items = items
        self.broken = broken or set()

    async def get_evidence(self, evidence_id: str) -> Evidence | None:
        if evidence_id in self.broken:
            raise EvidenceIntegrityError(f"La evidencia {evidence_id} no coincide con su hash sellado")
        if evidence_id == "EVD-DDDDDDDDDDDD":
            raise AuditStoreError("down")
        return self.items.get(evidence_id)


class FakeVulnRepo:
    async def get_vulnerability(self, _vulnerability_id):
        return None


@asynccontextmanager
async def api_client(store: FakeEvidenceStore):
    async with app.router.lifespan_context(app):
        app.state.authenticator = ApiKeyAuthenticator(
            [
                ApiCredential(
                    subject="test-operator",
                    role="operator",
                    key_sha256=ApiKeyAuthenticator.hash_api_key(OPERATOR_KEY),
                )
            ]
        )
        app.state.evidence_store = store
        app.state.evidence_signer = SIGNER
        app.state.vulnerability_repository = FakeVulnRepo()
        app.state.vulnerability_matcher = VulnerabilityMatcher(FakeRangeRepository([stored()]))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
        ) as client:
            yield client


@pytest.mark.asyncio
async def test_evidence_endpoint_confirms_from_sealed_evidence():
    inv, val = inventory(), nuclei_evidence()
    store = FakeEvidenceStore(
        {inv.evidence_id: inv, val.evidence_id: val},
        broken={"EVD-BBBBBBBBBBBB"},
    )
    body = {"vulnerability_id": CVE, "inventory_evidence_id": inv.evidence_id}
    async with api_client(store) as client:
        confirmed = await client.post(
            "/v1/analysis/evidence",
            json={**body, "validation_evidence_ids": [val.evidence_id]},
        )
        without_validation = await client.post("/v1/analysis/evidence", json=body)
        missing = await client.post(
            "/v1/analysis/evidence", json={**body, "validation_evidence_ids": ["EVD-AAAAAAAAAAAA"]}
        )
        tampered = await client.post(
            "/v1/analysis/evidence", json={**body, "validation_evidence_ids": ["EVD-BBBBBBBBBBBB"]}
        )
        down = await client.post(
            "/v1/analysis/evidence", json={**body, "validation_evidence_ids": ["EVD-DDDDDDDDDDDD"]}
        )
        not_inventory = await client.post(
            "/v1/analysis/evidence",
            json={"vulnerability_id": CVE, "inventory_evidence_id": val.evidence_id},
        )
        raw_payload = await client.post(
            "/v1/analysis/evidence",
            json={**body, "validation_evidence": [val.model_dump(mode="json")]},
        )

    assert confirmed.status_code == 200
    assert confirmed.json()["finding_status"] == "confirmed"
    # KEV/NVD info is absent here, but stored ranges carry source hashes.
    assert without_validation.json()["finding_status"] == "probable"
    assert missing.status_code == 404
    assert tampered.status_code == 409
    assert down.status_code == 503
    assert not_inventory.status_code == 422
    assert raw_payload.status_code == 422  # clients cannot inject evidence bodies


@pytest.mark.asyncio
async def test_evidence_case_endpoint_contains_verified_snapshot():
    inv, val = inventory(), nuclei_evidence()
    store = FakeEvidenceStore({inv.evidence_id: inv, val.evidence_id: val})
    body = {
        "vulnerability_id": CVE,
        "inventory_evidence_id": inv.evidence_id,
        "validation_evidence_ids": [val.evidence_id],
    }
    async with api_client(store) as client:
        response = await client.post("/v1/evidence/cases", json=body)

    assert response.status_code == 200
    bundle = response.json()
    assert bundle["schema_version"] == "cybercore.evidence-case/v2"
    assert bundle["case_id"].startswith("CASE-")
    assert bundle["assessment"]["finding_status"] == "confirmed"
    assert [item["evidence_id"] for item in bundle["evidence"]] == [
        inv.evidence_id, val.evidence_id
    ]
    assert len(bundle["bundle_sha256"]) == 64
    assert verify_evidence_case(EvidenceCaseBundle.model_validate(bundle), SIGNER.public_key)


@pytest.mark.asyncio
async def test_evidence_case_endpoint_needs_a_signing_key():
    inv = inventory()
    async with api_client(FakeEvidenceStore({inv.evidence_id: inv})) as client:
        app.state.evidence_signer = None
        response = await client.post(
            "/v1/evidence/cases",
            json={"vulnerability_id": CVE, "inventory_evidence_id": inv.evidence_id},
        )
        key = await client.get("/v1/evidence/signing-key")

    assert response.status_code == 503
    assert key.status_code == 503


@pytest.mark.asyncio
async def test_signing_key_endpoint_publishes_the_public_key():
    async with api_client(FakeEvidenceStore({})) as client:
        response = await client.get("/v1/evidence/signing-key")

    assert response.status_code == 200
    assert response.json()["signing_key_id"] == SIGNER.key_id
    assert "PRIVATE" not in response.json()["public_key_pem"]
