from app.api.models import Evidence
from app.core.evidence_analysis import EvidenceGapAnalyzer


def inventory_evidence(services=None):
    return Evidence(
        source="get_mock_inventory",
        target="192.168.10.25",
        data={
            "source": "simulated",
            "services": services
            if services is not None
            else [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "state": "open",
                }
            ],
        },
        sha256="a" * 64,
    )


def test_simulated_inventory_stays_candidate_with_explicit_cve_claim():
    assessment = EvidenceGapAnalyzer().analyze(
        inventory_evidence(),
        "CVE-2026-99999",
    )

    gap_codes = {gap.code for gap in assessment.missing_evidence}
    assert assessment.outcome == "need_more_evidence"
    assert assessment.finding_status == "candidate"
    assert assessment.can_confirm is False
    assert assessment.vulnerability_id == "CVE-2026-99999"
    assert "vulnerability_identifier" not in gap_codes
    assert {
        "real_inventory",
        "service_product_version",
        "authoritative_advisory",
        "affected_version_range",
        "independent_validation",
    } <= gap_codes
    assert "no permite afirmar" in assessment.conclusion


def test_missing_vulnerability_identifier_is_reported():
    assessment = EvidenceGapAnalyzer().analyze(inventory_evidence(), None)

    assert "vulnerability_identifier" in {
        gap.code for gap in assessment.missing_evidence
    }


def test_exact_service_versions_remove_only_the_fingerprint_gap():
    assessment = EvidenceGapAnalyzer().analyze(
        inventory_evidence(
            [
                {
                    "port": 443,
                    "state": "open",
                    "product": "Example Server",
                    "version": "1.2.3",
                }
            ]
        ),
        "CVE-2026-99999",
    )

    gap_codes = {gap.code for gap in assessment.missing_evidence}
    assert "service_product_version" not in gap_codes
    assert "authoritative_advisory" in gap_codes
    assert "independent_validation" in gap_codes
