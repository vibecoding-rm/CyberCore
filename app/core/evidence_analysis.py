from typing import Any

from app.api.models import Evidence, EvidenceAssessment, EvidenceGap


class EvidenceGapAnalyzer:
    def analyze(
        self,
        evidence: Evidence,
        vulnerability_id: str | None,
    ) -> EvidenceAssessment:
        services = self._services(evidence.data)
        open_services = [service for service in services if service.get("state") == "open"]
        observations = [
            f"El inventario declaró {len(open_services)} servicio(s) abierto(s).",
            "La presencia de un puerto abierto no demuestra una vulnerabilidad.",
        ]
        missing: list[EvidenceGap] = []

        if evidence.data.get("source") == "simulated":
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

        missing.extend(
            [
                EvidenceGap(
                    code="authoritative_advisory",
                    description=(
                        "No hay un advisory autoritativo vinculado a la observación."
                    ),
                    recommended_action=(
                        "Consultar primero al proveedor y después fuentes como CISA, "
                        "NVD u OSV, conservando procedencia y fecha."
                    ),
                ),
                EvidenceGap(
                    code="affected_version_range",
                    description=(
                        "No se comparó la versión instalada con un rango afectado."
                    ),
                    recommended_action=(
                        "Resolver el rango de versiones del advisory y compararlo sin "
                        "usar coincidencias de texto aproximadas."
                    ),
                ),
                EvidenceGap(
                    code="independent_validation",
                    description="No existe una validación independiente reproducible.",
                    recommended_action=(
                        "Realizar una comprobación segura y autorizada antes de elevar "
                        "el hallazgo a confirmado."
                    ),
                ),
            ]
        )

        return EvidenceAssessment(
            target=evidence.target,
            vulnerability_id=vulnerability_id,
            source_evidence_id=evidence.evidence_id,
            observations=observations,
            missing_evidence=missing,
            conclusion=(
                "La evidencia actual sólo permite mantener un candidato; no permite "
                "afirmar que el activo es vulnerable."
            ),
        )

    @staticmethod
    def _services(data: dict[str, Any]) -> list[dict[str, Any]]:
        services = data.get("services")
        if not isinstance(services, list):
            return []
        return [service for service in services if isinstance(service, dict)]
