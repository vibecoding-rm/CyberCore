from typing import Any
from urllib.parse import quote

import httpx

from app.intelligence.models import (
    AffectedRange,
    NormalizedVulnerability,
    parse_timestamp,
)

OSV_API_URL = "https://api.osv.dev"
_MAX_QUERY_PAGES = 5


class OsvError(RuntimeError):
    """Raised when the OSV API is unavailable or returns an invalid payload."""


def _range_entries(
    ecosystem: str,
    name: str,
    range_type: str,
    events: list[Any],
) -> list[AffectedRange]:
    kind = "semver" if range_type == "SEMVER" else "ecosystem"
    base = {
        "match_kind": "package",
        "product": name,
        "ecosystem": ecosystem,
        "range_type": kind,
    }
    entries: list[AffectedRange] = []
    start: str | None = None
    open_range = False
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            start = str(event["introduced"])
            open_range = True
        elif "fixed" in event and open_range:
            fixed = str(event["fixed"])
            entries.append(
                AffectedRange(
                    **base,
                    version_start_including=start,
                    version_end_excluding=fixed,
                    criteria=f"osv:{ecosystem}/{name} {range_type} [{start}, {fixed})",
                )
            )
            open_range = False
        elif "last_affected" in event and open_range:
            last = str(event["last_affected"])
            entries.append(
                AffectedRange(
                    **base,
                    version_start_including=start,
                    version_end_including=last,
                    criteria=f"osv:{ecosystem}/{name} {range_type} [{start}, {last}]",
                )
            )
            open_range = False
    if open_range:
        entries.append(
            AffectedRange(
                **base,
                version_start_including=start,
                criteria=f"osv:{ecosystem}/{name} {range_type} [{start}, ∞)",
            )
        )
    return entries


def _affected(affected: Any) -> list[AffectedRange]:
    ranges: list[AffectedRange] = []
    for item in affected if isinstance(affected, list) else []:
        package = item.get("package") if isinstance(item, dict) else None
        if not isinstance(package, dict):
            continue
        name, ecosystem = package.get("name"), package.get("ecosystem")
        if not isinstance(name, str) or not name or not isinstance(ecosystem, str):
            continue
        for version in item.get("versions", []) or []:
            if isinstance(version, str) and version:
                ranges.append(
                    AffectedRange(
                        match_kind="package",
                        product=name,
                        ecosystem=ecosystem,
                        range_type="exact",
                        exact_version=version,
                        criteria=f"osv:{ecosystem}/{name}@{version}",
                    )
                )
        for declared in item.get("ranges", []) or []:
            if not isinstance(declared, dict):
                continue
            # GIT ranges are commit hashes and cannot be compared with versions.
            if declared.get("type") not in {"SEMVER", "ECOSYSTEM"}:
                continue
            ranges.extend(
                _range_entries(ecosystem, name, declared["type"], declared.get("events", []))
            )
    return list(dict.fromkeys(ranges))


def parse_osv_record(record: dict[str, Any]) -> NormalizedVulnerability:
    vuln_id = record.get("id")
    if not isinstance(vuln_id, str) or not vuln_id:
        raise OsvError("El registro OSV no contiene un identificador válido")

    aliases = [
        alias.strip().upper() if alias.upper().startswith("CVE-") else alias.strip()
        for alias in (record.get("aliases") or []) + (record.get("related") or [])
        if isinstance(alias, str) and alias.strip()
    ]
    vector = next(
        (
            sev.get("score")
            for sev in record.get("severity") or []
            if isinstance(sev, dict) and str(sev.get("type", "")).startswith("CVSS_")
        ),
        None,
    )
    specific = record.get("database_specific")
    cwe_ids = specific.get("cwe_ids") if isinstance(specific, dict) else None
    return NormalizedVulnerability(
        vulnerability_id=vuln_id,
        source="osv",
        source_url=f"{OSV_API_URL}/v1/vulns/{quote(vuln_id, safe='')}",
        description=record.get("summary") or record.get("details"),
        cvss_vector=vector,
        cwe_ids=[c for c in cwe_ids or [] if isinstance(c, str) and c.startswith("CWE-")],
        aliases=list(dict.fromkeys(aliases)),
        published_at=parse_timestamp(record.get("published")),
        source_modified_at=parse_timestamp(record.get("modified")),
        ranges=_affected(record.get("affected")),
    )


class OsvClient:
    def __init__(
        self,
        base_url: str = OSV_API_URL,
        timeout_seconds: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ):
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
        )

    async def get_vulnerability(self, vuln_id: str) -> dict[str, Any] | None:
        response = await self._request("GET", f"/v1/vulns/{quote(vuln_id.strip(), safe='')}")
        if response is None:
            return None
        return self._json(response)

    async def query_package(
        self,
        ecosystem: str,
        name: str,
        version: str,
    ) -> list[dict[str, Any]]:
        """Exact OSV lookup of a package version; returns the matching records."""
        if not ecosystem or not name or not version:
            raise ValueError("ecosystem, name y version son obligatorios")
        records: list[dict[str, Any]] = []
        body: dict[str, Any] = {
            "package": {"ecosystem": ecosystem, "name": name},
            "version": version,
        }
        for _ in range(_MAX_QUERY_PAGES):
            response = await self._request("POST", "/v1/query", json=body)
            payload = self._json(response) if response is not None else {}
            vulns = payload.get("vulns") or []
            if not isinstance(vulns, list):
                raise OsvError("La respuesta de OSV contiene 'vulns' inválido")
            records.extend(v for v in vulns if isinstance(v, dict))
            token = payload.get("next_page_token")
            if not token:
                break
            body["page_token"] = token
        return records

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise OsvError("OSV devolvió JSON inválido") from exc
        if not isinstance(payload, dict):
            raise OsvError("OSV devolvió una respuesta que no es un objeto")
        return payload

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response | None:
        try:
            response = await self._client.request(method, path, **kwargs)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response
        except httpx.TimeoutException as exc:
            raise OsvError("OSV superó el timeout configurado") from exc
        except httpx.HTTPStatusError as exc:
            raise OsvError(f"OSV respondió con HTTP {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise OsvError("No se pudo conectar con OSV") from exc

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "OsvClient":
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()
