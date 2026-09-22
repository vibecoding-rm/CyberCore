import json
from pathlib import Path
from typing import Any
import httpx

from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository


CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


SAMPLE_BASELINE_VULNERABILITIES = [
    {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j2 Deserialization of Untrusted Data Vulnerability (Log4Shell)",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 contains a deserialization of untrusted data vulnerability leading to remote code execution.",
        "cwes": ["CWE-502", "CWE-400"],
        "cvss": 10.0,
        "epss": 0.97521,
    },
    {
        "cveID": "CVE-2023-34362",
        "vendorProject": "Progress",
        "product": "MOVEit Transfer",
        "vulnerabilityName": "Progress MOVEit Transfer SQL Injection Vulnerability",
        "dateAdded": "2023-06-02",
        "shortDescription": "Progress MOVEit Transfer contains an SQL injection vulnerability allowing unauthenticated remote access.",
        "cwes": ["CWE-89"],
        "cvss": 9.8,
        "epss": 0.96540,
    },
    {
        "cveID": "CVE-2023-4966",
        "vendorProject": "Citrix",
        "product": "NetScaler ADC and NetScaler Gateway",
        "vulnerabilityName": "Citrix NetScaler Sensitive Information Disclosure Vulnerability (CitrixBleed)",
        "dateAdded": "2023-10-18",
        "shortDescription": "Citrix NetScaler contains an information disclosure vulnerability that allows session token hijacking.",
        "cwes": ["CWE-119"],
        "cvss": 9.4,
        "epss": 0.95210,
    },
    {
        "cveID": "CVE-2024-21887",
        "vendorProject": "Ivanti",
        "product": "Connect Secure and Policy Secure",
        "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
        "dateAdded": "2024-01-11",
        "shortDescription": "A vulnerability in web components of Ivanti Connect Secure allows an authenticated administrator to execute arbitrary commands.",
        "cwes": ["CWE-77"],
        "cvss": 9.1,
        "epss": 0.94150,
    },
    {
        "cveID": "CVE-2023-38606",
        "vendorProject": "Apple",
        "product": "iOS, iPadOS, macOS",
        "vulnerabilityName": "Apple Multiple Products State Management Vulnerability",
        "dateAdded": "2023-07-25",
        "shortDescription": "Apple iOS, iPadOS, and macOS contain a state management vulnerability in the kernel leading to modification of sensitive kernel states.",
        "cwes": ["CWE-416"],
        "cvss": 8.8,
        "epss": 0.81230,
    },
]


class IngestionError(RuntimeError):
    """Raised when an external threat intelligence feed cannot be fetched or parsed."""


def parse_cisa_kev_json(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Valida y extrae registros de vulnerabilidad del formato oficial de CISA KEV."""
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise IngestionError("El catálogo CISA KEV no contiene una lista 'vulnerabilities' válida")
    
    parsed = []
    for item in vulnerabilities:
        cve = item.get("cveID")
        if not cve:
            continue
        parsed.append({
            "cveID": cve.strip().upper(),
            "vendorProject": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "vulnerabilityName": item.get("vulnerabilityName", ""),
            "dateAdded": item.get("dateAdded"),
            "shortDescription": item.get("shortDescription", ""),
            "cwes": item.get("cwes", []),
        })
    return parsed


async def fetch_cisa_kev_from_url(
    url: str = CISA_KEV_FEED_URL,
    timeout: float = 30.0,
) -> list[dict[str, Any]]:
    """Descarga y procesa el catálogo oficial CISA KEV desde la URL provista."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            return parse_cisa_kev_json(data)
    except Exception as exc:
        raise IngestionError(f"Error al descargar feed CISA KEV desde {url}") from exc


def load_cisa_kev_from_file(file_path: str | Path) -> list[dict[str, Any]]:
    """Carga y procesa un archivo JSON local de CISA KEV."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"No se encontró el archivo CISA KEV en {file_path}")
    
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return parse_cisa_kev_json(data)


async def fetch_epss_scores(
    cves: list[str],
    api_url: str = EPSS_API_URL,
    timeout: float = 15.0,
) -> list[dict[str, Any]]:
    """Consulta los puntajes EPSS actuales para una lista de CVEs usando la API de FIRST.org."""
    if not cves:
        return []

    cve_param = ",".join(cve.strip().upper() for cve in cves[:100])  # Batch capped at 100
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{api_url}?cve={cve_param}")
            response.raise_for_status()
            data = response.json()
            items = data.get("data", [])
            results = []
            for item in items:
                cve = item.get("cve")
                epss_val = item.get("epss")
                if cve and epss_val is not None:
                    results.append({
                        "cve": cve.strip().upper(),
                        "epss": float(epss_val),
                    })
            return results
    except Exception as exc:
        raise IngestionError("Error al consultar la API de EPSS") from exc


class VulnerabilityIngestService:
    def __init__(self, repository: PostgresVulnerabilityRepository):
        self.repository = repository

    async def ingest_cisa_kev(
        self,
        url: str | None = None,
        file_path: str | Path | None = None,
    ) -> int:
        """Ingiere el catálogo CISA KEV, ya sea desde archivo local o URL remota."""
        if file_path:
            records = load_cisa_kev_from_file(file_path)
        else:
            target_url = url or CISA_KEV_FEED_URL
            records = await fetch_cisa_kev_from_url(target_url)

        return await self.repository.bulk_upsert_kev(records)

    async def ingest_epss_for_cves(
        self,
        cves: list[str],
        api_url: str | None = None,
    ) -> int:
        """Consulta e ingiere los puntajes EPSS para los CVEs especificados."""
        if not cves:
            return 0
        records = await fetch_epss_scores(cves, api_url=api_url or EPSS_API_URL)
        return await self.repository.bulk_upsert_epss(records)

    async def seed_baseline_sample(self) -> dict[str, int]:
        """Siembra registros de referencia autoritativos de CVE/KEV/EPSS para el laboratorio."""
        kev_count = 0
        epss_count = 0
        for item in SAMPLE_BASELINE_VULNERABILITIES:
            cve = item["cveID"]
            await self.repository.upsert_vulnerability(
                vulnerability_id=cve,
                source="cisa_kev_baseline",
                title=item.get("vulnerabilityName"),
                description=item.get("shortDescription"),
                cvss=item.get("cvss"),
                epss=item.get("epss"),
                kev=True,
                cwe_ids=item.get("cwes", []),
                source_updated_at=item.get("dateAdded"),
            )
            kev_count += 1
            if item.get("epss") is not None:
                epss_count += 1

        return {"seeded_kev": kev_count, "seeded_epss": epss_count}
