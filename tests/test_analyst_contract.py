from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.analyst.contract import AnalystOutput, analyst_gate_violations
from app.analyst.template import template_analysis
from app.api.models import EvidenceAssessment, EvidenceGap
from app.core.evidence_bundle import build_evidence_case
from app.core.evidence_signing import EvidenceSigner
from tests.test_evidence_bundle import evidence

SIGNER = EvidenceSigner.generate()
GAP = EvidenceGap(
    code="independent_validation",
    description="No hay reproducción independiente.",
    recommended_action="Ejecutar la plantilla pasiva aprobada sobre el activo.",
)


def bundle(status="probable", gaps=(GAP,), conclusion="Hallazgo probable."):
    assessment = EvidenceAssessment(
        target="192.168.10.25",
        vulnerability_id="CVE-2024-6387",
        source_evidence_id="EVD-AAAAAAAAAAAA",
        observations=["OpenSSH 9.6p1 observado"],
        missing_evidence=list(gaps),
        conclusion=conclusion,
        finding_status=status,
    )
    return build_evidence_case(
        assessment, evidence("EVD-AAAAAAAAAAAA", "inspect_services"), [],
        {"vulnerability_id": "CVE-2024-6387", "aliases": ["GHSA-2x8c-95vh-gfv4"]}, SIGNER,
        generated_at=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )


def answer(**changes):
    base = {
        "summary": "OpenSSH 9.6p1 cae en el rango de CVE-2024-6387; sin validación independiente.",
        "evidence_interpretation": [
            {"evidence_id": "EVD-AAAAAAAAAAAA", "statement": "Nmap observó OpenSSH 9.6p1."}
        ],
        "missing_evidence": ["Reproducción independiente."],
        "recommended_actions": ["Aplicar la actualización del proveedor y reescanear."],
        "confidence_explanation": "Media: falta validación.",
    }
    return AnalystOutput.model_validate(base | changes)


def test_a_grounded_answer_passes():
    assert analyst_gate_violations(bundle(), answer()) == []


def test_the_contract_has_no_status_or_tool_fields():
    with pytest.raises(ValidationError):
        answer(finding_status="confirmed")
    with pytest.raises(ValidationError):
        answer(tool="inspect_services")


@pytest.mark.parametrize("changes, expected", [
    ({"evidence_interpretation": [{"evidence_id": "EVD-FFFFFFFFFFFF", "statement": "x"}]},
     "evidencia inexistente"),
    ({"summary": "También le afecta CVE-2023-38408."}, "identificador ajeno"),
    ({"summary": "El vecino 192.168.10.99 también expone SSH."}, "dirección ajena"),
    ({"summary": "El hallazgo está confirmado en el activo."}, "confirmación"),
    ({"missing_evidence": []}, "qué evidencia falta"),
    ({"recommended_actions": ["Explota el servicio para demostrarlo."]}, "acción ofensiva"),
])
def test_each_gate_catches_its_violation(changes, expected):
    violations = analyst_gate_violations(bundle(), answer(**changes))
    assert any(expected in violation for violation in violations), violations


def test_negated_confirmation_and_known_alias_are_allowed():
    result = answer(
        summary="No está confirmado; el aviso GHSA-2x8c-95vh-gfv4 equivale al CVE.",
    )
    assert analyst_gate_violations(bundle(), result) == []


def test_confirmation_is_allowed_when_the_engine_confirmed():
    confirmed = bundle(status="confirmed", gaps=(), conclusion="Hallazgo confirmado.")
    result = answer(summary="Hallazgo confirmado por reproducción independiente.", missing_evidence=[])
    assert analyst_gate_violations(confirmed, result) == []


@pytest.mark.parametrize("status, gaps, conclusion", [
    ("probable", (GAP,), "Hallazgo probable."),
    ("candidate", (), "Contradicción: Nuclei reprodujo la vulnerabilidad, pero la versión queda fuera."),
    ("confirmed", (), "Hallazgo confirmado."),
])
def test_the_template_control_passes_its_own_gates(status, gaps, conclusion):
    case = bundle(status=status, gaps=gaps, conclusion=conclusion)
    assert analyst_gate_violations(case, template_analysis(case)) == []
