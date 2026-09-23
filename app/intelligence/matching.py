from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from app.intelligence.cpe import parse_cpe
from app.intelligence.versions import Verdict, evaluate_range

MatchVerdict = Literal["affected", "not_affected", "indeterminate", "no_data"]

BACKPORT_NOTICE = (
    "Las distribuciones aplican parches sin cambiar la versión upstream (backports); "
    "una coincidencia de versión no confirma la vulnerabilidad."
)


class RangeEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    criteria: str
    range_type: str
    verdict: Verdict
    reason: str
    source_sha256: str | None = None


class VersionMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    product_key: str
    installed_version: str | None
    verdict: MatchVerdict
    evaluations: list[RangeEvaluation]
    notes: list[str]


class RangeRepository(Protocol):
    async def get_affected_ranges(
        self,
        vulnerability_id: str,
        *,
        vendor: str | None = None,
        product: str | None = None,
    ) -> list[dict[str, Any]]: ...


def evaluate_stored_range(installed: str, stored: dict[str, Any]) -> RangeEvaluation:
    common = {
        "source": stored["source"],
        "criteria": stored["criteria"],
        "range_type": stored["range_type"],
        "source_sha256": stored.get("source_sha256"),
    }
    if stored["range_type"] == "ecosystem":
        return RangeEvaluation(
            **common,
            verdict="indeterminate",
            reason=(
                f"El ecosistema {stored.get('ecosystem')} requiere un comparador "
                "de versiones propio que CyberCore aún no implementa."
            ),
        )

    verdict, reason = evaluate_range(
        installed,
        exact=stored.get("exact_version"),
        start_including=stored.get("version_start_including"),
        start_excluding=stored.get("version_start_excluding"),
        end_including=stored.get("version_end_including"),
        end_excluding=stored.get("version_end_excluding"),
    )
    if verdict == "affected" and stored.get("requires_platform"):
        return RangeEvaluation(
            **common,
            verdict="indeterminate",
            reason=f"{reason}, pero la fuente exige además una plataforma concreta no verificada.",
        )
    return RangeEvaluation(**common, verdict=verdict, reason=reason)


def aggregate(evaluations: list[RangeEvaluation]) -> MatchVerdict:
    if not evaluations:
        return "no_data"
    verdicts = {evaluation.verdict for evaluation in evaluations}
    if "affected" in verdicts:
        return "affected"
    if verdicts == {"not_affected"}:
        return "not_affected"
    return "indeterminate"


class VulnerabilityMatcher:
    def __init__(self, repository: RangeRepository):
        self.repository = repository

    async def match_cpe(self, vulnerability_id: str, cpe: str) -> VersionMatch:
        parsed = parse_cpe(cpe)
        if parsed is None:
            raise ValueError(f"CPE inválido: {cpe!r}")
        stored = await self.repository.get_affected_ranges(
            vulnerability_id,
            vendor=parsed.vendor,
            product=parsed.product,
        )
        return self._build(vulnerability_id, parsed.key, parsed.version, stored)

    async def match_package(
        self,
        vulnerability_id: str,
        ecosystem: str,
        name: str,
        version: str,
    ) -> VersionMatch:
        stored = [
            item
            for item in await self.repository.get_affected_ranges(vulnerability_id, product=name)
            if item.get("match_kind") == "package" and item.get("ecosystem") == ecosystem
        ]
        return self._build(vulnerability_id, f"{ecosystem}/{name}", version, stored)

    @staticmethod
    def _build(
        vulnerability_id: str,
        product_key: str,
        installed: str | None,
        stored: list[dict[str, Any]],
    ) -> VersionMatch:
        notes: list[str] = []
        if not stored:
            notes.append(
                f"No hay rangos almacenados para {product_key} en {vulnerability_id}; "
                "ingiere NVD/OSV antes de evaluar."
            )
            return VersionMatch(
                vulnerability_id=vulnerability_id,
                product_key=product_key,
                installed_version=installed,
                verdict="no_data",
                evaluations=[],
                notes=notes,
            )
        if installed is None:
            notes.append("El fingerprint no incluye versión; no se puede comparar el rango.")
            return VersionMatch(
                vulnerability_id=vulnerability_id,
                product_key=product_key,
                installed_version=None,
                verdict="indeterminate",
                evaluations=[],
                notes=notes,
            )

        evaluations = [evaluate_stored_range(installed, item) for item in stored]
        verdict = aggregate(evaluations)
        if verdict == "affected":
            notes.append(BACKPORT_NOTICE)
        return VersionMatch(
            vulnerability_id=vulnerability_id,
            product_key=product_key,
            installed_version=installed,
            verdict=verdict,
            evaluations=evaluations,
            notes=notes,
        )
