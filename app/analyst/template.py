"""Deterministic analyst: the control every LLM analyst must beat.

It fills the analyst contract from the engine's own assessment of a signed
evidence case, without a model. If an LLM cannot write explanations that
reviewers score better than these, CyberCore does not need an LLM analyst.
"""

from __future__ import annotations

from app.analyst.contract import AnalystOutput, EvidenceInterpretation
from app.api.models import EvidenceCaseBundle

_CONFIDENCE = {
    "confirmed": (
        "Alta: inventario real, versión dentro de un rango publicado con procedencia "
        "y reproducción independiente."
    ),
    "probable": "Media: hay indicios consistentes, pero falta alguna comprobación para confirmarlo.",
    "candidate": "Baja: la evidencia disponible no basta para afirmar que el activo está afectado.",
}


def template_analysis(bundle: EvidenceCaseBundle) -> AnalystOutput:
    assessment = bundle.assessment
    interpretations = []
    for item in bundle.evidence:
        role = (
            "evidencia fuente de la evaluación"
            if item.evidence_id == assessment.source_evidence_id
            else "validación independiente"
        )
        interpretations.append(EvidenceInterpretation(
            evidence_id=item.evidence_id,
            statement=f"{role} recogida por {item.source} sobre {item.target}.",
        ))
    contradictions = [
        observation for observation in assessment.observations
        if "contradic" in observation.lower()
    ]
    if "Contradicción" in assessment.conclusion and assessment.conclusion not in contradictions:
        contradictions.append(assessment.conclusion)
    missing = [gap.description for gap in assessment.missing_evidence]
    actions = [gap.recommended_action for gap in assessment.missing_evidence]
    if assessment.finding_status != "confirmed" and not missing:
        # e.g. a contradiction: nothing is absent, but a person must resolve it.
        missing = ["Revisión humana que resuelva por qué la evidencia no permite confirmar."]
        actions = ["Revisar manualmente el expediente antes de cerrar o escalar el hallazgo."]
    return AnalystOutput(
        summary=(
            f"{bundle.vulnerability_id} en {bundle.target}: estado "
            f"{assessment.finding_status}. {assessment.conclusion}"
        )[:800],
        evidence_interpretation=interpretations[:12],
        contradictions=contradictions[:8],
        missing_evidence=missing[:8],
        recommended_actions=actions[:8],
        confidence_explanation=_CONFIDENCE[assessment.finding_status],
    )
