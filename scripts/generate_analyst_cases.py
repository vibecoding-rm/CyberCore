"""Generate Analyst-Bench cases: signed evidence cases built by the real engine.

Each case runs the same code path as POST /v1/evidence/cases: stored NVD-style
ranges -> VulnerabilityMatcher -> EvidenceGapAnalyzer (with Nuclei validation)
-> build_evidence_case. Only the inputs are synthetic (inventories, Nuclei
results, catalogue rows); status, gaps and conclusion come from the engine.

Development and holdout use different CVE families, so no CVE, product or
advisory appears on both sides (docs/09_ANALYST_BENCH.md). Bundles are signed
with a key derived from a public seed: it proves nothing about origin and
must never be used outside the bench.

    python -m scripts.generate_analyst_cases
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.api.models import Evidence
from app.core.canonical import evidence_sha256
from app.core.evidence_analysis import EvidenceGapAnalyzer
from app.core.evidence_bundle import build_evidence_case
from app.core.evidence_signing import EvidenceSigner
from app.intelligence.matching import VulnerabilityMatcher

OUTPUT_DIR = Path("config/analyst_bench")
SEED = 20260925
GENERATED_AT = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)
BENCH_SIGNER = EvidenceSigner(
    Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"cybercore-analyst-bench-v1").digest())
)
CASES_PER_SPLIT = {"development": 40, "holdout": 60}


@dataclass(frozen=True)
class Family:
    split: str
    cve: str
    vendor: str
    product: str
    service: str  # product name as Nmap prints it
    port: int
    ranges: tuple[dict[str, str], ...]
    inside: str  # installed version inside the range
    outside: str  # installed version outside the range
    backport: str  # distro build string whose upstream version is inside
    title: str
    kev: bool
    cvss: float | None
    aliases: tuple[str, ...] = ()


# Catalogue values limited to facts stated in NVD/CISA for these CVEs; EPSS
# changes daily and is left out.
FAMILIES = [
    Family("development", "CVE-2021-41773", "apache", "http_server", "Apache httpd", 80,
           ({"exact_version": "2.4.49"},), "2.4.49", "2.4.58", "2.4.49-1ubuntu1",
           "Path traversal y divulgación de ficheros en Apache HTTP Server 2.4.49",
           kev=True, cvss=7.5),
    Family("development", "CVE-2024-6387", "openbsd", "openssh", "OpenSSH", 22,
           ({"version_start_including": "8.5p1", "version_end_excluding": "9.8p1"},),
           "9.6p1", "9.8p1", "9.6p1 Ubuntu 3ubuntu13.4",
           "Condición de carrera en el manejador de señales de sshd (regreSSHion)",
           kev=False, cvss=8.1),
    Family("development", "CVE-2014-0160", "openssl", "openssl", "OpenSSL", 443,
           ({"version_start_including": "1.0.1", "version_end_including": "1.0.1f"},),
           "1.0.1e", "1.0.1g", "1.0.1e-2+deb7u5",
           "Lectura fuera de límites en la extensión heartbeat de TLS (Heartbleed)",
           kev=True, cvss=7.5),
    Family("holdout", "CVE-2023-38408", "openbsd", "openssh", "OpenSSH", 22,
           ({"version_end_excluding": "9.3p2"},), "8.9p1", "9.6p1", "8.9p1 Ubuntu 3ubuntu0.3",
           "Carga de bibliotecas no confiables en el reenvío de ssh-agent de OpenSSH",
           kev=False, cvss=9.8),
    Family("holdout", "CVE-2011-2523", "vsftpd_project", "vsftpd", "vsftpd", 21,
           ({"exact_version": "2.3.4"},), "2.3.4", "3.0.5", "2.3.4-1",
           "Puerta trasera en el paquete distribuido de vsftpd 2.3.4",
           kev=False, cvss=None),
    Family("holdout", "CVE-2021-44790", "apache", "http_server", "Apache httpd", 443,
           ({"version_end_including": "2.4.51"},), "2.4.51", "2.4.52", "2.4.51-1~deb11u1",
           "Desbordamiento de búfer en el analizador multipart de mod_lua de Apache HTTP Server",
           kev=False, cvss=9.8),
]

INVENTORY = ("real", "simulated")
VERSION = ("inside", "outside", "backport", "missing")
ADVISORY = ("stored", "none")
VALIDATION = ("none", "active_match", "active_other_ip", "passive", "active_negative")


class StaticRanges:
    """In-memory stand-in for the range repository, same interface."""

    def __init__(self, family: Family, advisory: str):
        self.rows = [] if advisory == "none" else [
            {
                "vulnerability_id": family.cve,
                "source": "nvd",
                "match_kind": "cpe",
                "vendor": family.vendor,
                "product": family.product,
                "ecosystem": None,
                "range_type": "cpe",
                "exact_version": bounds.get("exact_version"),
                "version_start_including": bounds.get("version_start_including"),
                "version_start_excluding": bounds.get("version_start_excluding"),
                "version_end_including": bounds.get("version_end_including"),
                "version_end_excluding": bounds.get("version_end_excluding"),
                "requires_platform": False,
                "criteria": f"cpe:2.3:a:{family.vendor}:{family.product}:*:*:*:*:*:*:*:*",
                "source_sha256": hashlib.sha256(f"nvd:{family.cve}".encode()).hexdigest(),
            }
            for bounds in family.ranges
        ]

    async def get_affected_ranges(self, vulnerability_id, *, vendor=None, product=None):
        return [
            row for row in self.rows
            if row["vulnerability_id"] == vulnerability_id
            and (vendor is None or row["vendor"] == vendor)
            and (product is None or row["product"] == product)
        ]


def evidence_id(*parts: str) -> str:
    return "EVD-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:12].upper()


def sealed(eid: str, source: str, target: str, data: dict[str, Any], minutes: int) -> Evidence:
    return Evidence(
        evidence_id=eid,
        source=source,
        target=target,
        collected_at=GENERATED_AT - timedelta(minutes=minutes),
        data=data,
        sha256=evidence_sha256(data),
    )


def inventory_evidence(family: Family, case_key: str, target: str, inventory: str, version: str):
    installed = {"inside": family.inside, "outside": family.outside,
                 "backport": family.backport, "missing": None}[version]
    service: dict[str, Any] = {"port": family.port, "protocol": "tcp", "state": "open",
                               "product": family.service}
    if installed is not None:
        service["version"] = installed
        upstream = installed.split(" ")[0].split("-")[0]
        service["cpe"] = f"cpe:/a:{family.vendor}:{family.product}:{upstream}"
    data: dict[str, Any] = {"target": target, "services": [service]}
    source = "inspect_services"
    if inventory == "simulated":
        data["source"] = "simulated"
        source = "get_mock_inventory"
    return sealed(evidence_id(case_key, "inventory"), source, target, data, minutes=30)


def validation_evidence(family: Family, case_key: str, target: str, validation: str):
    if validation == "none":
        return []
    mode = "passive" if validation == "passive" else "active"
    matched_ip = "192.168.10.250" if validation == "active_other_ip" else target
    findings = [] if validation == "active_negative" else [{
        "template_id": family.cve,
        "cve_ids": [family.cve],
        "matched_at": f"{matched_ip}:{family.port}",
    }]
    data = {
        "target": target,
        "engine_version": "3.4.10",
        "templates": [{
            "id": family.cve,
            "mode": mode,
            "sha256": hashlib.sha256(f"template:{family.cve}:{mode}".encode()).hexdigest(),
            "path": f"http/cves/{family.cve.lower()}.yaml",
        }],
        "findings": findings,
    }
    return [sealed(evidence_id(case_key, "nuclei"), "run_nuclei_safe", target, data, minutes=10)]


def snapshot(family: Family) -> dict[str, Any]:
    info: dict[str, Any] = {"vulnerability_id": family.cve, "source": "nvd",
                            "title": family.title, "kev": family.kev}
    if family.cvss is not None:
        info["cvss"] = family.cvss
    if family.aliases:
        info["aliases"] = list(family.aliases)
    return info


async def build_case(family: Family, scenario: tuple[str, str, str, str], index: int) -> dict:
    inventory, version, advisory, validation = scenario
    case_key = f"{family.cve}|{'|'.join(scenario)}"
    target = f"192.168.10.{20 + index}"
    inv = inventory_evidence(family, case_key, target, inventory, version)
    checks = validation_evidence(family, case_key, target, validation)
    matcher = VulnerabilityMatcher(StaticRanges(family, advisory))
    matches = []
    for service in inv.data["services"]:
        if service.get("cpe"):
            matches.append(await matcher.match_cpe(family.cve, service["cpe"]))
    info = snapshot(family)
    assessment = EvidenceGapAnalyzer().analyze(
        inv, family.cve, vulnerability_info=info, version_matches=matches,
        validation_evidence=checks,
    )
    bundle = build_evidence_case(
        assessment, inv, checks, info, BENCH_SIGNER, generated_at=GENERATED_AT
    )
    return {
        "case_id": f"analyst-{family.split[:3]}-{index + 1:03d}",
        "split": family.split,
        "family": family.cve,
        "scenario": dict(zip(("inventory", "version", "advisory", "validation"), scenario)),
        "finding_status": assessment.finding_status,
        "bundle": bundle.model_dump(mode="json"),
    }


def pick_scenarios(rng: random.Random, count: int, families: list[Family]):
    """Balanced draw: every family, each status and the hard scenarios appear."""
    all_scenarios = list(itertools.product(INVENTORY, VERSION, ADVISORY, VALIDATION))
    # Real inventory is the interesting case; keep simulated ones to ~1 in 5.
    weights = [4 if s[0] == "real" else 1 for s in all_scenarios]
    picks: list[tuple[Family, tuple[str, str, str, str]]] = []
    # Guarantee the confirmation path and the main contradictions per family.
    must = [
        ("real", "inside", "stored", "active_match"),
        ("real", "outside", "stored", "active_match"),
        ("real", "backport", "stored", "none"),
        ("real", "inside", "stored", "active_negative"),
        ("real", "inside", "stored", "active_other_ip"),
        ("real", "missing", "stored", "passive"),
        ("simulated", "inside", "stored", "active_match"),
    ]
    for family in families:
        picks.extend((family, s) for s in must)
    seen = {(f.cve, s) for f, s in picks}
    while len(picks) < count:
        family = families[len(picks) % len(families)]
        scenario = rng.choices(all_scenarios, weights)[0]
        if (family.cve, scenario) in seen:
            continue
        seen.add((family.cve, scenario))
        picks.append((family, scenario))
    return picks[:count]


async def build_split(split: str) -> list[dict]:
    families = [f for f in FAMILIES if f.split == split]
    rng = random.Random(f"{SEED}:{split}")
    picks = pick_scenarios(rng, CASES_PER_SPLIT[split], families)
    return [await build_case(family, scenario, i) for i, (family, scenario) in enumerate(picks)]


def write_split(split: str, cases: list[dict]) -> str:
    path = OUTPUT_DIR / f"{split}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"generator": "scripts/generate_analyst_cases.py", "seed": SEED,
                "bench_signing_key_id": BENCH_SIGNER.key_id, "splits": {}}
    for split in CASES_PER_SPLIT:
        cases = asyncio.run(build_split(split))
        statuses: dict[str, int] = {}
        for case in cases:
            statuses[case["finding_status"]] = statuses.get(case["finding_status"], 0) + 1
        manifest["splits"][split] = {
            "cases": len(cases),
            "families": sorted({c["family"] for c in cases}),
            "finding_status": dict(sorted(statuses.items())),
            "sha256": write_split(split, cases),
        }
        print(split, manifest["splits"][split])
    (OUTPUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )


if __name__ == "__main__":
    main()
