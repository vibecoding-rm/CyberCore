from datetime import datetime, timezone

from app.api.models import Evidence, EvidenceAssessment
from app.core.canonical import evidence_sha256
from app.core.evidence_bundle import build_evidence_case, verify_evidence_case


def evidence(evidence_id: str, source: str) -> Evidence:
    data = {"source": "real", "services": []}
    return Evidence(
        evidence_id=evidence_id,
        source=source,
        target="192.168.10.25",
        collected_at=datetime(2026, 9, 25, tzinfo=timezone.utc),
        data=data,
        sha256=evidence_sha256(data),
    )


def assessment() -> EvidenceAssessment:
    return EvidenceAssessment(
        target="192.168.10.25",
        vulnerability_id="CVE-2024-6387",
        source_evidence_id="EVD-AAAAAAAAAAAA",
        observations=["evidencia revisada"],
        missing_evidence=[],
        conclusion="Hallazgo probable.",
        finding_status="probable",
    )


def test_bundle_is_stable_for_the_same_snapshot_and_verifiable():
    inv = evidence("EVD-AAAAAAAAAAAA", "inspect_services")
    val = evidence("EVD-BBBBBBBBBBBB", "run_nuclei_safe")
    generated = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)

    first = build_evidence_case(
        assessment(), inv, [val], {"vulnerability_id": "CVE-2024-6387", "cvss": 8.1},
        generated_at=generated,
    )
    second = build_evidence_case(
        assessment(), inv, [val], {"vulnerability_id": "CVE-2024-6387", "cvss": 8.1},
        generated_at=generated,
    )

    assert first.case_id == second.case_id
    assert first.bundle_sha256 == second.bundle_sha256
    assert verify_evidence_case(first) is True


def test_verifier_detects_bundle_tampering():
    bundle = build_evidence_case(
        assessment(), evidence("EVD-AAAAAAAAAAAA", "inspect_services"), [], None,
        generated_at=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )
    tampered = bundle.model_copy(update={"target": "192.168.10.99"})

    assert verify_evidence_case(tampered) is False


def test_verifier_checks_each_sealed_evidence_body():
    bundle = build_evidence_case(
        assessment(), evidence("EVD-AAAAAAAAAAAA", "inspect_services"), [], None,
        generated_at=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )
    broken_evidence = bundle.evidence[0].model_copy(update={"data": {"services": ["changed"]}})
    # Rebuilding the envelope hash cannot hide a stale evidence seal.
    rebuilt = build_evidence_case(
        bundle.assessment, broken_evidence, [], None, generated_at=bundle.generated_at
    )

    assert verify_evidence_case(rebuilt) is False
