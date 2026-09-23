from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.api.models import Evidence

NUCLEI_SOURCE = "run_nuclei_safe"
ValidationStatus = Literal["validated", "not_reproduced", "not_applicable"]


class ValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ValidationStatus
    evidence_ids: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)


def assess_nuclei_validation(
    evidence_items: list[Evidence],
    target: str,
    vulnerability_id: str | None,
) -> ValidationResult:
    """Decide whether sealed Nuclei evidence independently reproduces the CVE.

    Only a real (non-simulated) run against the same target, whose finding is
    classified with this CVE and comes from an allowlisted *active* template,
    counts as validation. A passive detection is another fingerprint, not proof.
    A silent active run is recorded as "not reproduced", never as a false
    positive: templates can miss vulnerable configurations.
    """
    observations: list[str] = []
    if not evidence_items:
        return ValidationResult(status="not_applicable")
    if vulnerability_id is None:
        return ValidationResult(
            status="not_applicable",
            observations=["Sin CVE indicado, la validación de Nuclei no puede asociarse."],
        )

    validated_ids: list[str] = []
    silent_active_ids: list[str] = []
    for evidence in evidence_items:
        data: dict[str, Any] = evidence.data
        label = f"Evidencia {evidence.evidence_id}"
        if evidence.source != NUCLEI_SOURCE:
            observations.append(f"{label} no procede de {NUCLEI_SOURCE}; no valida.")
            continue
        if data.get("source") == "simulated":
            observations.append(f"{label} es una ejecución simulada de Nuclei; no valida.")
            continue
        if evidence.target != target:
            observations.append(
                f"{label} se obtuvo contra {evidence.target}, no contra {target}; no valida."
            )
            continue

        modes = {
            t.get("id"): t.get("mode")
            for t in data.get("templates") or []
            if isinstance(t, dict)
        }
        hashes = {
            t.get("id"): t.get("sha256")
            for t in data.get("templates") or []
            if isinstance(t, dict)
        }
        relevant = [
            f
            for f in data.get("findings") or []
            if isinstance(f, dict) and vulnerability_id in (f.get("cve_ids") or [])
        ]
        active_hits = [f for f in relevant if modes.get(f.get("template_id")) == "active"]
        if active_hits:
            hit = active_hits[0]
            template_id = hit.get("template_id")
            validated_ids.append(evidence.evidence_id)
            observations.append(
                f"Nuclei {data.get('engine_version', '?')} reprodujo {vulnerability_id} con la "
                f"plantilla activa {template_id} (sha256 {str(hashes.get(template_id))[:12]}…) "
                f"en {hit.get('matched_at')}."
            )
            continue
        if relevant:
            observations.append(
                f"{label}: detección pasiva de {vulnerability_id}; no equivale a validación."
            )
            continue
        if any(tid == vulnerability_id and mode == "active" for tid, mode in modes.items()):
            silent_active_ids.append(evidence.evidence_id)
            observations.append(
                f"{label}: la plantilla activa {vulnerability_id} no reprodujo la "
                "vulnerabilidad. No prueba ausencia; puede requerir otra configuración."
            )

    if validated_ids:
        return ValidationResult(
            status="validated", evidence_ids=validated_ids, observations=observations
        )
    if silent_active_ids:
        return ValidationResult(
            status="not_reproduced", evidence_ids=silent_active_ids, observations=observations
        )
    return ValidationResult(status="not_applicable", observations=observations)
