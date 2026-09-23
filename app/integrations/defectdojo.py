import json
from datetime import date
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.api.models import Evidence, EvidenceAssessment

SCAN_TYPE = "Generic Findings Import"
EXPORTABLE_STATUSES = {"probable", "confirmed"}


class DefectDojoError(RuntimeError):
    """Raised when DefectDojo is unavailable or rejects an import."""


class DefectDojoSettings(BaseModel):
    """DefectDojo connection chosen by the administrator, never by the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    base_url: str
    api_token: SecretStr
    product_type: str = Field(default="CyberCore", min_length=1)
    product: str = Field(default="CyberCore Lab", min_length=1)
    engagement: str = Field(default="CyberCore automated", min_length=1)
    verify_tls: bool = True
    ca_bundle: str | None = None
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)


def severity_from_cvss(cvss: float | None) -> str:
    """CVSS v3 qualitative bands; without a score the finding is Info."""
    if cvss is None:
        return "Info"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Info"


def _cwe_number(cwe_ids: list[str]) -> int | None:
    for cwe in cwe_ids:
        number = cwe.removeprefix("CWE-")
        if number.isdigit():
            return int(number)
    return None


def build_generic_finding(
    assessment: EvidenceAssessment,
    inventory: Evidence,
    vulnerability_info: dict[str, Any] | None,
) -> dict[str, Any]:
    """Map a server-side assessment to one DefectDojo Generic Findings item."""
    if assessment.finding_status not in EXPORTABLE_STATUSES:
        raise ValueError(
            f"Sólo se exportan hallazgos probable o confirmed; estado actual: "
            f"{assessment.finding_status}"
        )
    if assessment.vulnerability_id is None:
        raise ValueError("Un hallazgo exportable necesita un CVE")

    info = vulnerability_info or {}
    cve = assessment.vulnerability_id
    lines = [
        f"**Estado CyberCore:** {assessment.finding_status}",
        f"**Conclusión:** {assessment.conclusion}",
        "",
        "**Observaciones:**",
        *(f"- {obs}" for obs in assessment.observations),
    ]
    if assessment.missing_evidence:
        lines += ["", "**Evidencia pendiente:**"]
        lines += [f"- `{gap.code}`: {gap.description}" for gap in assessment.missing_evidence]
    lines += [
        "",
        "**Evidencia sellada (SHA-256):**",
        f"- Inventario `{inventory.evidence_id}` ({inventory.source}): `{inventory.sha256}`",
        *(f"- Validación `{eid}`" for eid in assessment.validation_evidence_ids),
    ]

    finding: dict[str, Any] = {
        "title": f"{cve} en {assessment.target}",
        "description": "\n".join(lines),
        "severity": severity_from_cvss(info.get("cvss")),
        "date": date.today().isoformat(),
        "cve": cve,
        "unique_id_from_tool": f"cybercore:{assessment.target}:{cve}",
        "vuln_id_from_tool": cve,
        "active": True,
        "verified": assessment.finding_status == "confirmed",
        "endpoints": [{"host": assessment.target}],
        "tags": ["cybercore", assessment.finding_status],
        "mitigation": (
            "Aplicar la corrección del proveedor y verificar con un nuevo inventario "
            "y una validación independiente."
        ),
    }
    cwe = _cwe_number(info.get("cwe_ids") or [])
    if cwe is not None:
        finding["cwe"] = cwe
    vector = info.get("cvss_vector")
    if isinstance(vector, str) and vector.startswith("CVSS:3"):
        finding["cvssv3"] = vector
    if info.get("kev"):
        finding["known_exploited"] = True
    aliases = [a for a in info.get("aliases") or [] if a != cve]
    if aliases:
        finding["vulnerability_ids"] = aliases
    return finding


class DefectDojoClient:
    def __init__(
        self,
        settings: DefectDojoSettings,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.settings = settings
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            base_url=settings.base_url.rstrip("/"),
            timeout=settings.timeout_seconds,
            verify=settings.ca_bundle or settings.verify_tls,
        )

    async def reimport(self, findings: list[dict[str, Any]], test_title: str) -> dict[str, Any]:
        """Reimport into a test dedicated to one asset and CVE.

        Reimport may close findings missing from the new file, so sharing a test
        across exports would silently mitigate unrelated findings; one test per
        (asset, CVE) keeps each export isolated and idempotent.
        """
        payload = json.dumps({"findings": findings}, ensure_ascii=False).encode("utf-8")
        data = {
            "scan_type": SCAN_TYPE,
            "product_type_name": self.settings.product_type,
            "product_name": self.settings.product,
            "engagement_name": self.settings.engagement,
            "test_title": test_title,
            "auto_create_context": "true",
            "minimum_severity": "Info",
            "close_old_findings": "false",
        }
        try:
            response = await self._client.post(
                "/api/v2/reimport-scan/",
                headers={
                    "Authorization": f"Token {self.settings.api_token.get_secret_value()}"
                },
                data=data,
                files={"file": ("cybercore.json", payload, "application/json")},
            )
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            raise DefectDojoError(
                f"DefectDojo rechazó la importación (HTTP {exc.response.status_code})"
            ) from exc
        except httpx.RequestError as exc:
            raise DefectDojoError("No se pudo conectar con DefectDojo") from exc
        except ValueError as exc:
            raise DefectDojoError("DefectDojo devolvió JSON inválido") from exc
        return {
            "test_id": body.get("test_id") or body.get("test"),
            "engagement_id": body.get("engagement_id"),
            "product_id": body.get("product_id"),
            "statistics": body.get("statistics"),
        }

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def dojo_test_title(target: str, vulnerability_id: str) -> str:
    return f"CyberCore {target} {vulnerability_id}"
