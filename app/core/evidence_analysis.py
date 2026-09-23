from typing import Any, Literal

from app.api.models import Evidence, EvidenceAssessment, EvidenceGap
from app.core.validation import ValidationResult, assess_nuclei_validation
from app.intelligence.matching import VersionMatch

_VERDICT_TEXT = {
    "affected": "dentro de un rango afectado",
    "not_affected": "fuera de todos los rangos afectados",
    "indeterminate": "sin comparación concluyente",
    "no_data": "sin rangos almacenados",
}

RangeState = Literal["affected", "not_affected", "unresolved"]
FindingStatus = Literal["candidate", "probable", "confirmed"]

_CANDIDATE = (
    "La evidencia actual sólo permite mantener un candidato; no permite "
    "afirmar que el activo es vulnerable."
)


def decide_status(
    *,
    simulated: bool,
    range_state: RangeState,
    advisory_resolved: bool,
    validated: bool,
) -> tuple[FindingStatus, str]:
    """Deterministic promotion rule; the model never chooses the status.

    confirmed = real inventory + version inside a published range + authoritative
    source with provenance + independent reproduction by an active template.
    """
    if simulated:
        return "candidate", _CANDIDATE
    if validated:
        if range_state == "affected" and advisory_resolved:
            return "confirmed", (
                "Producto y versión dentro de un rango publicado con procedencia "
                "verificable y reproducción independiente con Nuclei: hallazgo confirmado."
            )
        if range_state == "not_affected":
            return "candidate", (
                "Contradicción: Nuclei reprodujo la vulnerabilidad, pero la versión "
                "observada queda fuera de los rangos publicados. Requiere revisión humana."
            )
        return "probable", (
            "Nuclei reprodujo la vulnerabilidad, pero falta resolver la versión o el "
            "advisory autoritativo antes de confirmarla."
        )
    if range_state == "affected":
        return "probable", (
            "El producto y la versión caen en un rango afectado publicado: el "
            "hallazgo es probable, pero falta validación independiente para "
            "confirmarlo."
        )
    return "candidate", _CANDIDATE


class EvidenceGapAnalyzer:
    def analyze(
        self,
        evidence: Evidence,
        vulnerability_id: str | None,
        vulnerability_info: dict[str, Any] | None = None,
        version_matches: list[VersionMatch] | None = None,
        validation_evidence: list[Evidence] | None = None,
    ) -> EvidenceAssessment:
        services = self._services(evidence.data)
        open_services = [service for service in services if service.get("state") == "open"]
        observations = [
            f"El inventario declaró {len(open_services)} servicio(s) abierto(s).",
            "La presencia de un puerto abierto no demuestra una vulnerabilidad.",
        ]

        if vulnerability_info:
            if vulnerability_info.get("kev"):
                observations.append(
                    f"La vulnerabilidad {vulnerability_id} está en el catálogo CISA KEV (explotación activa conocida)."
                )
            if vulnerability_info.get("epss") is not None:
                epss = vulnerability_info["epss"]
                observations.append(
                    f"Puntaje EPSS: {epss:.4f} ({epss * 100:.2f}% de probabilidad de explotación en 30 días)."
                )
            if vulnerability_info.get("cvss") is not None:
                observations.append(
                    f"Puntuación base CVSS: {vulnerability_info['cvss']}."
                )
            if vulnerability_info.get("title"):
                observations.append(
                    f"Información de referencia: {vulnerability_info['title']}."
                )
        matches = version_matches or []
        for match in matches:
            observations.append(
                f"{match.product_key} {match.installed_version or '(sin versión)'}: "
                f"{_VERDICT_TEXT[match.verdict]} de {match.vulnerability_id}."
            )
            observations.extend(match.notes)
        range_resolved = any(m.verdict in {"affected", "not_affected"} for m in matches)
        range_state: RangeState = "unresolved"
        if any(m.verdict == "affected" for m in matches):
            range_state = "affected"
        elif matches and all(m.verdict == "not_affected" for m in matches):
            range_state = "not_affected"
        # Stored NVD/OSV ranges carry the hash of their source record; KEV is
        # CISA's own catalog. Either links the claim to an authoritative source.
        advisory_resolved = any(m.evaluations for m in matches) or bool(
            vulnerability_info and vulnerability_info.get("kev")
        )
        validation: ValidationResult = assess_nuclei_validation(
            validation_evidence or [],
            evidence.target,
            vulnerability_id,
        )
        observations.extend(validation.observations)
        validated = validation.status == "validated"
        simulated = evidence.data.get("source") == "simulated"

        missing: list[EvidenceGap] = []

        if simulated:
            missing.append(
                EvidenceGap(
                    code="real_inventory",
                    description="El inventario disponible es simulado.",
                    recommended_action=(
                        "Recolectar inventario autorizado desde una fuente real y "
                        "conservar su evidencia original."
                    ),
                )
            )

        if vulnerability_id is None:
            missing.append(
                EvidenceGap(
                    code="vulnerability_identifier",
                    description="No se indicó una vulnerabilidad concreta para evaluar.",
                    recommended_action=(
                        "Identificar un CVE candidato a partir del producto y la versión, "
                        "sin inferirlo sólo por el puerto."
                    ),
                )
            )

        if not open_services or any(
            not service.get("product") or not service.get("version")
            for service in open_services
        ):
            missing.append(
                EvidenceGap(
                    code="service_product_version",
                    description=(
                        "Faltan el producto y la versión exactos de al menos un servicio."
                    ),
                    recommended_action=(
                        "Obtener un fingerprint reproducible del servicio y validar su "
                        "versión por una segunda fuente cuando sea posible."
                    ),
                )
            )

        if not advisory_resolved:
            missing.append(
                EvidenceGap(
                    code="authoritative_advisory",
                    description=(
                        "No hay un advisory autoritativo vinculado a la observación."
                    ),
                    recommended_action=(
                        "Consultar primero al proveedor y después fuentes como CISA, "
                        "NVD u OSV, conservando procedencia y fecha."
                    ),
                )
            )
        if not range_resolved:
            missing.append(
                EvidenceGap(
                    code="affected_version_range",
                    description=(
                        "No se comparó la versión instalada con un rango afectado."
                    ),
                    recommended_action=(
                        "Resolver el rango de versiones del advisory y compararlo sin "
                        "usar coincidencias de texto aproximadas."
                    ),
                )
            )
        if not validated:
            missing.append(
                EvidenceGap(
                    code="independent_validation",
                    description="No existe una validación independiente reproducible.",
                    recommended_action=(
                        "Ejecutar run_nuclei_safe con una plantilla activa del allowlist "
                        "y aprobación, y aportar su evidencia sellada."
                    ),
                )
            )

        status, conclusion = decide_status(
            simulated=simulated,
            range_state=range_state,
            advisory_resolved=advisory_resolved,
            validated=validated,
        )
        confirmed = status == "confirmed"
        return EvidenceAssessment(
            outcome="sufficient_evidence" if confirmed else "need_more_evidence",
            finding_status=status,
            can_confirm=confirmed,
            target=evidence.target,
            vulnerability_id=vulnerability_id,
            source_evidence_id=evidence.evidence_id,
            observations=observations,
            missing_evidence=missing,
            version_matches=matches,
            validation_evidence_ids=validation.evidence_ids,
            conclusion=conclusion,
        )

    @staticmethod
    def _services(data: dict[str, Any]) -> list[dict[str, Any]]:
        services = data.get("services")
        if not isinstance(services, list):
            return []
        return [service for service in services if isinstance(service, dict)]
