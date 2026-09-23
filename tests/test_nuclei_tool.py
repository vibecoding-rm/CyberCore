import hashlib
import json
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.models import ToolRequest
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.tools import nuclei as nuclei_module
from app.tools.nuclei import NucleiSafeTool, build_target_url, parse_nuclei_jsonl
from app.tools.nuclei_catalog import (
    AllowedTemplate,
    NucleiTemplateCatalog,
    NucleiTemplateError,
)
from tests.test_broker_nmap_integration import InMemoryBudgetCoordinator, InMemoryJournal

HTTP_TEMPLATE = b"""id: CVE-2021-41773
info:
  name: Apache 2.4.49 - Path Traversal
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/icons/.%2e/%2e%2e/etc/passwd"
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
"""


def write_template(root: Path, rel: str, content: bytes) -> str:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def catalog_with(root: Path, content: bytes = HTTP_TEMPLATE, template_id: str = "CVE-2021-41773",
                 digest: str | None = None) -> NucleiTemplateCatalog:
    rel = "http/cves/2021/CVE-2021-41773.yaml"
    actual = write_template(root, rel, content)
    return NucleiTemplateCatalog(
        root,
        [
            AllowedTemplate(
                id=template_id,
                path=rel,
                sha256=digest or actual,
                mode="active",
                description="Apache path traversal",
            )
        ],
    )


VALID_ARGS = {
    "target": "192.168.10.25",
    "port": 80,
    "scheme": "http",
    "templates": ["CVE-2021-41773"],
}


def test_allowlist_entry_rejects_path_escape():
    for bad in ("../etc/passwd.yaml", "/abs/t.yaml", "C:/t.yaml", r"a\..\b.yaml", "http/t.yml"):
        with pytest.raises(ValidationError):
            AllowedTemplate(id="x", path=bad, sha256="a" * 64, mode="passive", description="d")


def test_verify_accepts_pinned_http_template(tmp_path):
    verified = catalog_with(tmp_path).verify("CVE-2021-41773")
    assert verified.content == HTTP_TEMPLATE
    assert verified.mode == "active"


def test_verify_rejects_modified_template(tmp_path):
    catalog = catalog_with(tmp_path, digest="0" * 64)
    with pytest.raises(NucleiTemplateError, match="hash"):
        catalog.verify("CVE-2021-41773")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"id: CVE-2021-41773\ncode:\n  - engine: [sh]\n", "protocolos no permitidos"),
        (b"id: CVE-2021-41773\nheadless:\n  - steps: []\n", "protocolos no permitidos"),
        (b"id: CVE-2021-41773\nflow: http(1)\nhttp: []\n", "protocolos no permitidos"),
        (b"id: CVE-2021-41773\ntcp:\n  - inputs: []\n", "no es una plantilla HTTP"),
        (b"id: CVE-2021-41773\nself-contained: true\nhttp: []\n", "self-contained"),
        (
            b"id: CVE-2021-41773\nhttp:\n  - self-contained: true\n    raw: []\n",
            "self-contained",
        ),
        (b"id: other-id\nhttp: []\n", "declara id"),
    ],
)
def test_verify_rejects_unsafe_templates(tmp_path, content, message):
    catalog = catalog_with(tmp_path, content=content)
    with pytest.raises(NucleiTemplateError, match=message):
        catalog.verify("CVE-2021-41773")


def test_catalog_from_missing_file_is_empty(tmp_path):
    catalog = NucleiTemplateCatalog.from_yaml(tmp_path / "missing.yaml", tmp_path)
    assert catalog.templates == {}


def test_project_allowlist_loads():
    catalog = NucleiTemplateCatalog.from_yaml("config/nuclei_templates.yaml", "~/nuclei-templates")
    assert isinstance(catalog.templates, dict)


def test_arguments_are_strict_and_allowlisted(tmp_path):
    tool = NucleiSafeTool(catalog_with(tmp_path))

    normalized = tool.validate_arguments(VALID_ARGS)
    assert normalized["templates"] == ["CVE-2021-41773"]

    rejected = [
        {**VALID_ARGS, "templates": ["cves/"]},
        {**VALID_ARGS, "templates": []},
        {**VALID_ARGS, "target": "example.com"},
        {**VALID_ARGS, "scheme": "ftp"},
        {**VALID_ARGS, "port": 0},
        {**VALID_ARGS, "flags": ["-code"]},
        {**VALID_ARGS, "templates": ["CVE-2021-41773", "CVE-2021-41773"]},
    ]
    for arguments in rejected:
        with pytest.raises((ValidationError, NucleiTemplateError)):
            tool.validate_arguments(arguments)


def test_build_target_url_brackets_ipv6():
    assert build_target_url("192.168.10.25", 8443, "https") == "https://192.168.10.25:8443"
    assert build_target_url("fe80::1", 80, "http") == "http://[fe80::1]:80"


def test_parse_nuclei_jsonl_extracts_and_truncates():
    line = json.dumps(
        {
            "template-id": "CVE-2021-41773",
            "info": {
                "name": "Apache 2.4.49",
                "severity": "high",
                "classification": {"cve-id": ["cve-2021-41773"]},
            },
            "type": "http",
            "matched-at": "http://192.168.10.25:80/icons/x",
            "matcher-name": "passwd",
            "response": "x" * 10_000,
        }
    )
    findings = parse_nuclei_jsonl(f"[INF] banner\n{line}\nnot json {{\n")

    assert len(findings) == 1
    assert findings[0]["cve_ids"] == ["CVE-2021-41773"]
    assert findings[0]["severity"] == "high"
    assert len(findings[0]["response"]) < 4200


@pytest.mark.asyncio
async def test_mock_mode_sends_no_traffic_but_verifies_templates(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("mock mode must not spawn processes")

    monkeypatch.setattr(nuclei_module.subprocess, "run", forbidden)
    result = await NucleiSafeTool(catalog_with(tmp_path)).execute(VALID_ARGS)

    assert result["source"] == "simulated"
    assert result["run_mode"] == "active"
    assert result["templates"][0]["sha256"] == hashlib.sha256(HTTP_TEMPLATE).hexdigest()


@pytest.mark.asyncio
async def test_local_mode_runs_fixed_flags_on_verified_copy(tmp_path, monkeypatch):
    calls: list[list[str]] = []
    staged_contents: list[bytes] = []
    finding = json.dumps(
        {"template-id": "CVE-2021-41773", "info": {"severity": "high"}, "matched-at": "http://x"}
    )

    def fake_run(cmd, capture_output, timeout):
        calls.append(cmd)
        if cmd[1] == "-version":
            return subprocess.CompletedProcess(cmd, 0, b"", b"Nuclei Engine Version: v3.4.10\n")
        staged = Path(cmd[cmd.index("-t") + 1])
        staged_contents.append(staged.read_bytes())
        return subprocess.CompletedProcess(cmd, 0, f"{finding}\n".encode(), b"")

    monkeypatch.setattr(nuclei_module.subprocess, "run", fake_run)
    monkeypatch.setattr(nuclei_module, "find_nuclei_executable", lambda: "nuclei")

    tool = NucleiSafeTool(catalog_with(tmp_path), mode="local")
    result = await tool.execute(VALID_ARGS)

    scan = calls[1]
    assert scan[scan.index("-u") + 1] == "http://192.168.10.25:80"
    for flag in ("-no-interactsh", "-disable-redirects", "-disable-update-check", "-jsonl"):
        assert flag in scan
    for flag in ("-code", "-headless", "-lfa", "-allow-local-file-access", "-env-vars", "-fr"):
        assert flag not in scan
    assert scan[scan.index("-config") + 1].endswith("nuclei-runtime.yaml")
    assert staged_contents == [HTTP_TEMPLATE]
    assert not Path(scan[scan.index("-t") + 1]).exists()  # staging dir removed
    assert result["engine_version"] == "3.4.10"
    assert result["total_findings"] == 1


@pytest.mark.asyncio
async def test_local_mode_refuses_tampered_template_before_running(tmp_path, monkeypatch):
    catalog = catalog_with(tmp_path)
    (tmp_path / "http/cves/2021/CVE-2021-41773.yaml").write_bytes(HTTP_TEMPLATE + b"# changed\n")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("nuclei must not run with a tampered template")

    monkeypatch.setattr(nuclei_module.subprocess, "run", forbidden)
    with pytest.raises(NucleiTemplateError):
        await NucleiSafeTool(catalog, mode="local").execute(VALID_ARGS)


POLICY = """
version: 1
scope:
  allowed_networks: [192.168.10.0/24]
  denied_networks: [0.0.0.0/8]
  allow_hostnames: false
budgets:
  max_targets_per_request: 256
  max_duration_seconds: 300
  max_parallel_jobs: 2
  max_requests_per_hour: 30
tools:
  run_nuclei_safe:
    enabled: true
    risk: high
    approval_required: true
"""


@pytest.mark.asyncio
async def test_broker_requires_approval_and_blocks_out_of_scope(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(POLICY, encoding="utf-8")
    broker = ToolBroker(
        policy=PolicyEngine(policy_file),
        tools=[NucleiSafeTool(catalog_with(tmp_path / "templates"))],
        journal=InMemoryJournal(),
        budget_coordinator=InMemoryBudgetCoordinator(),
        tool_mode="mock",
    )

    def request(arguments):
        return ToolRequest(
            request_id=uuid4(),
            requested_by="operador-test",
            tool="run_nuclei_safe",
            arguments=arguments,
        )

    pending = await broker.execute(request(VALID_ARGS))
    public = await broker.execute(request({**VALID_ARGS, "target": "8.8.8.8"}))
    unlisted = await broker.execute(request({**VALID_ARGS, "templates": ["tech-detect"]}))

    assert pending.status == "approval_required"
    assert public.status == "denied"
    assert unlisted.status == "denied"
    assert "allowlist" in unlisted.decision.reason
