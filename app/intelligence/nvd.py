import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from app.intelligence.cpe import parse_cpe
from app.intelligence.models import (
    AffectedRange,
    NormalizedVulnerability,
    parse_timestamp,
)

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")

# NVD publishes 5 requests per rolling 30 s without a key and 50 with one.
_INTERVAL_WITHOUT_KEY = 6.0
_INTERVAL_WITH_KEY = 0.6
_METRIC_PREFERENCE = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_RANGE_FIELDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


class NvdError(RuntimeError):
    """Raised when the NVD API is unavailable or returns an invalid payload."""


def _select_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key in _METRIC_PREFERENCE:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        primary = [e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"]
        entry = (primary or entries)[0]
        data = entry.get("cvssData") if isinstance(entry, dict) else None
        if isinstance(data, dict) and data.get("baseScore") is not None:
            return float(data["baseScore"]), data.get("vectorString"), data.get("version")
    return None, None, None


def _cwe_ids(weaknesses: Any) -> list[str]:
    found: list[str] = []
    for weakness in weaknesses if isinstance(weaknesses, list) else []:
        for desc in weakness.get("description", []) if isinstance(weakness, dict) else []:
            value = desc.get("value") if isinstance(desc, dict) else None
            if isinstance(value, str) and value.startswith("CWE-") and value not in found:
                found.append(value)
    return found


def _ranges(configurations: Any) -> list[AffectedRange]:
    ranges: list[AffectedRange] = []
    for config in configurations if isinstance(configurations, list) else []:
        if not isinstance(config, dict):
            continue
        # An AND configuration means "vulnerable product running on platform X";
        # the platform half cannot be verified from a service fingerprint.
        requires_platform = config.get("operator") == "AND"
        for node in config.get("nodes", []):
            if not isinstance(node, dict) or node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                if not isinstance(match, dict) or match.get("vulnerable") is not True:
                    continue
                criteria = match.get("criteria")
                cpe = parse_cpe(criteria) if isinstance(criteria, str) else None
                if cpe is None:
                    continue
                bounds = {field: match.get(field) for field in _RANGE_FIELDS}
                has_bounds = any(isinstance(v, str) and v for v in bounds.values())
                if cpe.version and not has_bounds:
                    range_type, exact = "exact", cpe.version
                elif has_bounds:
                    range_type, exact = "cpe", None
                else:
                    # Wildcard version with no bounds: every version is affected.
                    range_type, exact = "cpe", None
                    bounds["versionStartIncluding"] = "0"
                ranges.append(
                    AffectedRange(
                        match_kind="cpe",
                        vendor=cpe.vendor,
                        product=cpe.product,
                        range_type=range_type,
                        exact_version=exact,
                        version_start_including=bounds["versionStartIncluding"],
                        version_start_excluding=bounds["versionStartExcluding"],
                        version_end_including=bounds["versionEndIncluding"],
                        version_end_excluding=bounds["versionEndExcluding"],
                        requires_platform=requires_platform,
                        criteria=criteria,
                    )
                )
    return list(dict.fromkeys(ranges))


def parse_nvd_cve(payload: dict[str, Any]) -> NormalizedVulnerability | None:
    """Normalize one CVE from an NVD CVE API 2.0 response; None if absent."""
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise NvdError("La respuesta de NVD no contiene 'vulnerabilities'")
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve") if isinstance(vulnerabilities[0], dict) else None
    if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
        raise NvdError("La respuesta de NVD no contiene un CVE válido")

    description = next(
        (
            d.get("value")
            for d in cve.get("descriptions", [])
            if isinstance(d, dict) and d.get("lang") == "en"
        ),
        None,
    )
    cvss, vector, version = _select_cvss(cve.get("metrics") or {})
    cve_id = cve["id"].strip().upper()
    return NormalizedVulnerability(
        vulnerability_id=cve_id,
        source="nvd",
        source_url=f"{NVD_CVE_API_URL}?cveId={cve_id}",
        description=description,
        cvss=cvss,
        cvss_vector=vector,
        cvss_version=version,
        cwe_ids=_cwe_ids(cve.get("weaknesses")),
        published_at=parse_timestamp(cve.get("published")),
        source_modified_at=parse_timestamp(cve.get("lastModified")),
        ranges=_ranges(cve.get("configurations")),
    )


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = NVD_CVE_API_URL,
        timeout_seconds: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.base_url = base_url
        self.min_interval = _INTERVAL_WITH_KEY if api_key else _INTERVAL_WITHOUT_KEY
        self._sleep = sleep
        self._last_request: float | None = None
        headers = {"apiKey": api_key} if api_key else None
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            timeout=timeout_seconds,
            headers=headers,
        )

    async def fetch_cve(self, cve_id: str) -> tuple[NormalizedVulnerability | None, dict[str, Any]]:
        """Return the normalized CVE and the raw payload kept as evidence."""
        cve_clean = cve_id.strip().upper()
        if not CVE_ID_RE.match(cve_clean):
            raise ValueError(f"Identificador CVE inválido: {cve_id!r}")
        await self._throttle()
        try:
            response = await self._client.get(self.base_url, params={"cveId": cve_clean})
            if response.status_code == 404:
                return None, {}
            response.raise_for_status()
            payload = response.json()
        except httpx.TimeoutException as exc:
            raise NvdError("NVD superó el timeout configurado") from exc
        except httpx.HTTPStatusError as exc:
            raise NvdError(f"NVD respondió con HTTP {exc.response.status_code}") from exc
        except (httpx.RequestError, ValueError) as exc:
            raise NvdError("No se pudo obtener una respuesta válida de NVD") from exc
        if not isinstance(payload, dict):
            raise NvdError("La respuesta de NVD no es un objeto JSON")
        return parse_nvd_cve(payload), payload

    async def _throttle(self) -> None:
        now = time.monotonic()
        if self._last_request is not None:
            wait = self.min_interval - (now - self._last_request)
            if wait > 0:
                await self._sleep(wait)
        self._last_request = time.monotonic()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "NvdClient":
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()
