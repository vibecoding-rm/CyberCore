"""Build and verify portable, signed evidence cases from already sealed records."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.api.models import Evidence, EvidenceAssessment, EvidenceCaseBundle
from app.core.canonical import evidence_sha256
from app.core.evidence_signing import EvidenceSigner, key_id, verify_signature
from app.core.tool_broker import ToolBroker


SCHEMA_VERSION = "cybercore.evidence-case/v2"
_UNSIGNED = {"bundle_sha256", "signature"}
_VULNERABILITY_FIELDS = (
    "vulnerability_id",
    "source",
    "title",
    "description",
    "cvss",
    "cvss_vector",
    "cvss_version",
    "epss",
    "kev",
    "cwe_ids",
    "aliases",
    "published_at",
    "source_updated_at",
    "ingested_at",
)


def _vulnerability_snapshot(info: dict[str, Any] | None) -> dict[str, Any] | None:
    if not info:
        return None
    return {field: info[field] for field in _VULNERABILITY_FIELDS if field in info}


def _bundle_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(ToolBroker.canonical_json(payload)).hexdigest()


def _case_id(vulnerability_id: str, evidence: list[Evidence]) -> str:
    identity = {
        "vulnerability_id": vulnerability_id,
        "evidence_ids": sorted(item.evidence_id for item in evidence),
    }
    return f"CASE-{_bundle_digest(identity)[:16].upper()}"


def build_evidence_case(
    assessment: EvidenceAssessment,
    inventory: Evidence,
    validation: list[Evidence],
    vulnerability_info: dict[str, Any] | None,
    signer: EvidenceSigner,
    *,
    generated_at: datetime | None = None,
) -> EvidenceCaseBundle:
    if assessment.vulnerability_id is None:
        raise ValueError("El expediente necesita un identificador de vulnerabilidad")
    evidence = [inventory, *validation]
    case_id = _case_id(assessment.vulnerability_id, evidence)
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "generated_at": generated_at or datetime.now(timezone.utc),
        "target": assessment.target,
        "vulnerability_id": assessment.vulnerability_id,
        "assessment": assessment,
        "vulnerability_snapshot": _vulnerability_snapshot(vulnerability_info),
        "evidence": evidence,
        "integrity_algorithm": "sha256",
        "signature_algorithm": "ed25519",
        "signing_key_id": signer.key_id,
    }
    json_payload = EvidenceCaseBundle.model_validate(
        unsigned | {"bundle_sha256": "0" * 64, "signature": "A" * 88}
    ).model_dump(mode="json", exclude=_UNSIGNED)
    digest = _bundle_digest(json_payload)
    return EvidenceCaseBundle.model_validate(
        unsigned | {"bundle_sha256": digest, "signature": signer.sign(digest)}
    )


def verify_evidence_case(bundle: EvidenceCaseBundle, public_key: Ed25519PublicKey) -> bool:
    return not evidence_case_integrity_issues(bundle, public_key)


def evidence_case_integrity_issues(
    bundle: EvidenceCaseBundle, public_key: Ed25519PublicKey
) -> list[str]:
    """Verify the signature, envelope, sealed bodies and internal references."""
    issues: list[str] = []
    if bundle.signing_key_id != key_id(public_key):
        issues.append("El expediente está firmado con otra clave")
    elif not verify_signature(public_key, bundle.bundle_sha256, bundle.signature):
        issues.append("La firma del expediente no es válida")
    payload = bundle.model_dump(mode="json", exclude=_UNSIGNED)
    if _bundle_digest(payload) != bundle.bundle_sha256:
        issues.append("El hash del expediente no coincide")
    if bundle.case_id != _case_id(bundle.vulnerability_id, bundle.evidence):
        issues.append("El case_id no corresponde a la vulnerabilidad y evidencias")

    ids = [item.evidence_id for item in bundle.evidence]
    if len(ids) != len(set(ids)):
        issues.append("El expediente contiene IDs de evidencia duplicados")
    for item in bundle.evidence:
        if evidence_sha256(item.data) != item.sha256:
            issues.append(f"La evidencia {item.evidence_id} no coincide con su hash")
        if item.target != bundle.target:
            issues.append(f"La evidencia {item.evidence_id} pertenece a otro objetivo")

    if bundle.assessment.source_evidence_id not in ids:
        issues.append("La evidencia fuente de la evaluación no está incluida")
    missing_validation = set(bundle.assessment.validation_evidence_ids) - set(ids)
    if missing_validation:
        issues.append("Faltan evidencias de validación referenciadas por la evaluación")
    if bundle.assessment.target != bundle.target:
        issues.append("El objetivo de la evaluación no coincide con el expediente")
    if bundle.assessment.vulnerability_id != bundle.vulnerability_id:
        issues.append("La vulnerabilidad de la evaluación no coincide con el expediente")
    return issues
