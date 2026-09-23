import asyncio
import json
import logging
import re
import shutil
import subprocess
import tempfile
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.tools.nuclei_catalog import NucleiTemplateCatalog, VerifiedTemplate

logger = logging.getLogger(__name__)

MAX_TEMPLATES_PER_RUN = 10
MAX_FINDINGS = 200
MAX_RAW_CHARS = 4096
MAX_OUTPUT_BYTES = 512 * 1024
_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")

# Fixed flags. The model and the operator only choose target, port, scheme and
# allowlisted template ids; nothing here is derived from free text.
_SAFE_FLAGS = (
    "-jsonl",
    "-silent",
    "-no-color",
    "-disable-update-check",
    "-no-interactsh",      # no out-of-band callbacks to external servers
    "-disable-redirects",  # a redirect could leave the authorized target
    "-rate-limit", "5",
    "-concurrency", "1",
    "-bulk-size", "1",
    "-timeout", "10",
    "-retries", "0",
    "-max-host-error", "5",
)


class NucleiArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    target: str = Field(min_length=1, max_length=45)
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"]
    templates: list[str] = Field(min_length=1, max_length=MAX_TEMPLATES_PER_RUN)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return str(ip_address(value))

    @field_validator("templates")
    @classmethod
    def normalize_templates(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("La lista de plantillas contiene duplicados")
        return sorted(value)


def find_nuclei_executable() -> str:
    exe = shutil.which("nuclei")
    if exe:
        return exe
    raise RuntimeError("Ejecutable nuclei no encontrado en el sistema")


def build_target_url(target: str, port: int, scheme: str) -> str:
    host = f"[{target}]" if ":" in target else target
    return f"{scheme}://{host}:{port}"


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_RAW_CHARS:
        return value[:MAX_RAW_CHARS] + "…[truncado]"
    return value


def parse_nuclei_jsonl(output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Línea JSONL de Nuclei inválida descartada")
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        classification = (
            info.get("classification") if isinstance(info.get("classification"), dict) else {}
        )
        findings.append(
            {
                "template_id": item.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "cve_ids": [
                    str(cve).upper() for cve in classification.get("cve-id") or [] if cve
                ],
                "type": item.get("type"),
                "matched_at": item.get("matched-at"),
                "matcher_name": item.get("matcher-name"),
                "extracted_results": item.get("extracted-results") or [],
                "timestamp": item.get("timestamp"),
                "request": _truncate(item.get("request")),
                "response": _truncate(item.get("response")),
            }
        )
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


class NucleiSafeTool:
    """Runs only allowlisted, hash-pinned HTTP templates against one authorized IP."""

    name = "run_nuclei_safe"
    timeout_seconds = 120.0

    def __init__(
        self,
        catalog: NucleiTemplateCatalog,
        mode: Literal["mock", "local"] = "mock",
        runtime_config: Path | str = "config/nuclei-runtime.yaml",
    ):
        self.catalog = catalog
        self.mode = mode
        self.runtime_config = Path(runtime_config)

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        parsed = NucleiArguments.model_validate(arguments)
        for template_id in parsed.templates:
            self.catalog.get(template_id)
        return parsed.model_dump(mode="json")

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        url = build_target_url(arguments["target"], arguments["port"], arguments["scheme"])
        # Verify right before running: the bytes that pass the hash check are
        # the exact bytes Nuclei loads, copied to a private directory.
        verified = [self.catalog.verify(t) for t in arguments["templates"]]
        templates_meta = [
            {"id": t.id, "mode": t.mode, "sha256": t.sha256, "path": t.path} for t in verified
        ]
        run_mode = "active" if any(t.mode == "active" for t in verified) else "passive"

        if self.mode == "mock":
            return self._mock_result(arguments, url, templates_meta, run_mode)

        nuclei_bin = find_nuclei_executable()
        engine_version = await self._engine_version(nuclei_bin)
        with tempfile.TemporaryDirectory(prefix="cybercore-nuclei-") as workdir:
            template_args = self._stage_templates(Path(workdir), verified)
            cmd = [
                nuclei_bin,
                "-config", str(self.runtime_config.resolve()),
                "-u", url,
                *template_args,
                *_SAFE_FLAGS,
            ]
            try:
                completed = await asyncio.to_thread(
                    subprocess.run,
                    cmd,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(
                    f"Nuclei superó el timeout de {self.timeout_seconds}s"
                ) from exc

        if completed.returncode != 0:
            err = completed.stderr.decode("utf-8", errors="replace").strip()[-500:]
            raise RuntimeError(f"Error al ejecutar Nuclei: {err}")

        stdout = completed.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        findings = parse_nuclei_jsonl(stdout)
        return {
            "target": arguments["target"],
            "url": url,
            "scan_type": "run_nuclei_safe",
            "run_mode": run_mode,
            "engine_version": engine_version,
            "templates": templates_meta,
            "findings": findings,
            "total_findings": len(findings),
            "command_flags": list(_SAFE_FLAGS),
            "raw_output": stdout,
            "raw_output_truncated": len(completed.stdout) > MAX_OUTPUT_BYTES,
        }

    @staticmethod
    def _stage_templates(workdir: Path, verified: list[VerifiedTemplate]) -> list[str]:
        args: list[str] = []
        for template in verified:
            staged = workdir / f"{template.id}.yaml"
            staged.write_bytes(template.content)
            args.extend(["-t", str(staged)])
        return args

    async def _engine_version(self, nuclei_bin: str) -> str:
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                [nuclei_bin, "-version"],
                capture_output=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "unknown"
        text = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
        match = _VERSION_RE.search(text)
        return match.group(1) if match else "unknown"

    @staticmethod
    def _mock_result(
        arguments: dict[str, Any],
        url: str,
        templates_meta: list[dict[str, Any]],
        run_mode: str,
    ) -> dict[str, Any]:
        first = templates_meta[0]["id"]
        findings = [
            {
                "template_id": first,
                "name": f"Resultado simulado de {first}",
                "severity": "info",
                "cve_ids": [first.upper()] if first.upper().startswith("CVE-") else [],
                "type": "http",
                "matched_at": f"{url}/",
                "matcher_name": "simulated",
                "extracted_results": [],
                "timestamp": None,
                "request": None,
                "response": None,
            }
        ]
        return {
            "target": arguments["target"],
            "url": url,
            "source": "simulated",
            "scan_type": "run_nuclei_safe (mock)",
            "run_mode": run_mode,
            "engine_version": "mock",
            "templates": templates_meta,
            "findings": findings,
            "total_findings": len(findings),
            "command_flags": list(_SAFE_FLAGS),
            "raw_output": "",
            "raw_output_truncated": False,
            "notice": "No se ejecutó Nuclei ni se envió tráfico real.",
        }
