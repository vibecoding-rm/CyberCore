from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

from app.api.models import Evidence
from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.core.evidence_analysis import EvidenceGapAnalyzer
from app.intelligence.matching import BACKPORT_NOTICE, VulnerabilityMatcher
from app.main import app

OPERATOR_KEY = "operator-key-with-at-least-32-characters"
CVE = "CVE-2024-6387"


def stored(**overrides: Any) -> dict[str, Any]:
    base = {
        "vulnerability_id": CVE,
        "source": "nvd",
        "match_kind": "cpe",
        "vendor": "openbsd",
        "product": "openssh",
        "ecosystem": None,
        "range_type": "cpe",
        "exact_version": None,
        "version_start_including": "8.6",
        "version_start_excluding": None,
        "version_end_including": "9.8",
        "version_end_excluding": None,
        "requires_platform": False,
        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        "source_sha256": "a" * 64,
    }
    return {**base, **overrides}


class FakeRangeRepository:
    def __init__(self, ranges: list[dict[str, Any]]):
        self.ranges = ranges
        self.calls: list[tuple[str, str | None, str | None]] = []

    async def get_affected_ranges(self, vulnerability_id, *, vendor=None, product=None):
        self.calls.append((vulnerability_id, vendor, product))
        return [
            r
            for r in self.ranges
            if (vendor is None or r["vendor"] == vendor)
            and (product is None or r["product"] == product)
        ]


@pytest.mark.asyncio
async def test_cpe_inside_range_is_affected_with_backport_notice():
    repo = FakeRangeRepository([stored()])
    match = await VulnerabilityMatcher(repo).match_cpe(CVE, "cpe:/a:openbsd:openssh:9.6p1")

    assert repo.calls == [(CVE, "openbsd", "openssh")]
    assert match.verdict == "affected"
    assert match.installed_version == "9.6p1"
    assert BACKPORT_NOTICE in match.notes
    assert match.evaluations[0].source_sha256 == "a" * 64


@pytest.mark.asyncio
async def test_cpe_outside_all_ranges_is_not_affected():
    repo = FakeRangeRepository([stored(), stored(range_type="exact", exact_version="8.5p1",
                                               version_start_including=None, version_end_including=None)])
    match = await VulnerabilityMatcher(repo).match_cpe(CVE, "cpe:/a:openbsd:openssh:8.4")
    assert match.verdict == "not_affected"


@pytest.mark.asyncio
async def test_ambiguous_suffix_is_indeterminate():
    repo = FakeRangeRepository([stored()])
    match = await VulnerabilityMatcher(repo).match_cpe(CVE, "cpe:/a:openbsd:openssh:9.8p1")
    assert match.verdict == "indeterminate"


@pytest.mark.asyncio
async def test_platform_dependent_range_never_reports_affected():
    repo = FakeRangeRepository([stored(requires_platform=True)])
    match = await VulnerabilityMatcher(repo).match_cpe(CVE, "cpe:/a:openbsd:openssh:9.6p1")
    assert match.verdict == "indeterminate"
    assert "plataforma" in match.evaluations[0].reason


@pytest.mark.asyncio
async def test_missing_data_and_missing_version():
    empty = await VulnerabilityMatcher(FakeRangeRepository([])).match_cpe(
        CVE, "cpe:/a:openbsd:openssh:9.6p1"
    )
    assert empty.verdict == "no_data"

    versionless = await VulnerabilityMatcher(FakeRangeRepository([stored()])).match_cpe(
        CVE, "cpe:/a:openbsd:openssh"
    )
    assert versionless.verdict == "indeterminate"


@pytest.mark.asyncio
async def test_invalid_cpe_is_rejected():
    with pytest.raises(ValueError):
        await VulnerabilityMatcher(FakeRangeRepository([])).match_cpe(CVE, "openssh 9.6")


@pytest.mark.asyncio
async def test_package_match_filters_ecosystem_and_skips_ecosystem_ranges():
    repo = FakeRangeRepository(
        [
            stored(match_kind="package", vendor=None, product="lodash", ecosystem="npm",
                   range_type="semver", version_start_including="0",
                   version_end_including=None, version_end_excluding="4.17.21"),
            stored(match_kind="package", vendor=None, product="lodash", ecosystem="Debian:12",
                   range_type="ecosystem", version_start_including="0",
                   version_end_including=None, version_end_excluding="1:4.17.21"),
        ]
    )
    matcher = VulnerabilityMatcher(repo)

    npm = await matcher.match_package(CVE, "npm", "lodash", "4.17.20")
    assert npm.verdict == "affected" and len(npm.evaluations) == 1

    debian = await matcher.match_package(CVE, "Debian:12", "lodash", "4.17.20")
    assert debian.verdict == "indeterminate"


def _evidence(source: str, cpe: str) -> Evidence:
    return Evidence(
        source="nmap",
        target="192.168.10.25",
        sha256="b" * 64,
        data={
            "source": source,
            "services": [
                {"port": 22, "state": "open", "product": "OpenSSH", "version": "9.6p1", "cpe": cpe}
            ],
        },
    )


@pytest.mark.asyncio
async def test_real_inventory_in_range_becomes_probable_never_confirmed():
    match = await VulnerabilityMatcher(FakeRangeRepository([stored()])).match_cpe(
        CVE, "cpe:/a:openbsd:openssh:9.6p1"
    )
    assessment = EvidenceGapAnalyzer().analyze(
        _evidence("nmap", "cpe:/a:openbsd:openssh:9.6p1"), CVE, version_matches=[match]
    )

    codes = {gap.code for gap in assessment.missing_evidence}
    assert assessment.finding_status == "probable"
    assert assessment.can_confirm is False
    assert "affected_version_range" not in codes
    assert {"authoritative_advisory", "independent_validation"} <= codes
    assert assessment.version_matches == [match]


@pytest.mark.asyncio
async def test_simulated_inventory_stays_candidate_even_when_in_range():
    match = await VulnerabilityMatcher(FakeRangeRepository([stored()])).match_cpe(
        CVE, "cpe:/a:openbsd:openssh:9.6p1"
    )
    assessment = EvidenceGapAnalyzer().analyze(
        _evidence("simulated", "cpe:/a:openbsd:openssh:9.6p1"), CVE, version_matches=[match]
    )
    assert assessment.finding_status == "candidate"


@pytest.mark.asyncio
async def test_indeterminate_match_keeps_range_gap():
    match = await VulnerabilityMatcher(FakeRangeRepository([stored()])).match_cpe(
        CVE, "cpe:/a:openbsd:openssh:9.8p1"
    )
    assessment = EvidenceGapAnalyzer().analyze(
        _evidence("nmap", "cpe:/a:openbsd:openssh:9.8p1"), CVE, version_matches=[match]
    )
    assert assessment.finding_status == "candidate"
    assert "affected_version_range" in {gap.code for gap in assessment.missing_evidence}


@asynccontextmanager
async def api_client(repo: FakeRangeRepository):
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
        app.state.vulnerability_matcher = VulnerabilityMatcher(repo)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
        ) as client:
            yield client


@pytest.mark.asyncio
async def test_match_endpoint():
    async with api_client(FakeRangeRepository([stored()])) as client:
        ok = await client.post(
            "/v1/vulnerabilities/match",
            json={"vulnerability_id": CVE, "cpe": "cpe:/a:openbsd:openssh:9.6p1"},
        )
        both = await client.post(
            "/v1/vulnerabilities/match",
            json={"vulnerability_id": CVE, "cpe": "cpe:/a:x:y:1", "package": "lodash"},
        )
        bad_cpe = await client.post(
            "/v1/vulnerabilities/match",
            json={"vulnerability_id": CVE, "cpe": "not-a-cpe-at-all"},
        )
        anonymous = await client.post(
            "/v1/vulnerabilities/match",
            json={"vulnerability_id": CVE, "cpe": "cpe:/a:openbsd:openssh:9.6p1"},
            headers={"Authorization": ""},
        )

    assert ok.status_code == 200 and ok.json()["verdict"] == "affected"
    assert both.status_code == 422
    assert bad_cpe.status_code == 422
    assert anonymous.status_code == 401
