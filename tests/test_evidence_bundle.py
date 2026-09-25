from datetime import datetime, timezone

from app.api.models import Evidence, EvidenceAssessment
from app.core.canonical import evidence_sha256
from app.core.evidence_bundle import _UNSIGNED, _bundle_digest, build_evidence_case, verify_evidence_case
from app.core.evidence_signing import EvidenceSigner

SIGNER = EvidenceSigner.generate()
PUBLIC = SIGNER.public_key


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
        assessment(), inv, [val], {"vulnerability_id": "CVE-2024-6387", "cvss": 8.1}, SIGNER,
        generated_at=generated,
    )
    second = build_evidence_case(
        assessment(), inv, [val], {"vulnerability_id": "CVE-2024-6387", "cvss": 8.1}, SIGNER,
        generated_at=generated,
    )

    assert first.case_id == second.case_id
    assert first.bundle_sha256 == second.bundle_sha256
    assert verify_evidence_case(first, PUBLIC) is True


def test_verifier_detects_bundle_tampering():
    bundle = build_evidence_case(
        assessment(), evidence("EVD-AAAAAAAAAAAA", "inspect_services"), [], None, SIGNER,
        generated_at=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )
    tampered = bundle.model_copy(update={"target": "192.168.10.99"})

    assert verify_evidence_case(tampered, PUBLIC) is False


def test_verifier_checks_each_sealed_evidence_body():
    bundle = build_evidence_case(
        assessment(), evidence("EVD-AAAAAAAAAAAA", "inspect_services"), [], None, SIGNER,
        generated_at=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )
    broken_evidence = bundle.evidence[0].model_copy(update={"data": {"services": ["changed"]}})
    # Rebuilding the envelope hash cannot hide a stale evidence seal.
    rebuilt = build_evidence_case(
        bundle.assessment, broken_evidence, [], None, SIGNER, generated_at=bundle.generated_at
    )

    assert verify_evidence_case(rebuilt, PUBLIC) is False


def test_recomputing_the_hash_after_an_edit_does_not_forge_the_signature():
    bundle = build_evidence_case(
        assessment(), evidence("EVD-AAAAAAAAAAAA", "inspect_services"), [], None, SIGNER,
        generated_at=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )
    edited = bundle.model_copy(update={
        "assessment": bundle.assessment.model_copy(update={"finding_status": "confirmed"})
    })
    rehashed = edited.model_copy(update={
        "bundle_sha256": _bundle_digest(edited.model_dump(mode="json", exclude=_UNSIGNED))
    })

    assert verify_evidence_case(rehashed, PUBLIC) is False


def test_a_bundle_signed_by_another_key_is_rejected():
    impostor = EvidenceSigner.generate()
    bundle = build_evidence_case(
        assessment(), evidence("EVD-AAAAAAAAAAAA", "inspect_services"), [], None, impostor,
        generated_at=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )

    assert verify_evidence_case(bundle, impostor.public_key) is True
    assert verify_evidence_case(bundle, PUBLIC) is False
