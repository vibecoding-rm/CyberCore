from contextlib import contextmanager
from uuid import uuid4
from xml.etree import ElementTree as ET

import pytest
from pydantic import SecretStr, ValidationError

from app.api.models import ToolRequest
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.tools.greenbone import (
    GreenboneError,
    GreenboneResultsTool,
    GreenboneSettings,
    GreenboneStartTaskTool,
    ensure_hosts_within,
)
from tests.test_broker_nmap_integration import InMemoryBudgetCoordinator, InMemoryJournal

TASK_ID = "2b5c1f0a-3c1e-4d7b-9f00-000000000001"
REPORT_ID = "7d0e9a11-8a2f-4c55-9b00-000000000002"
SETTINGS = GreenboneSettings(user="cybercore", password=SecretStr("pw"), host="gvmd.test")


class FakeGmp:
    def __init__(self, hosts="192.168.10.25", status="Done", results_xml=""):
        self.hosts = hosts
        self.status = status
        self.results_xml = results_xml
        self.started: list[str] = []

    def get_task(self, task_id):
        if task_id != TASK_ID:
            return ET.fromstring("<get_tasks_response/>")
        return ET.fromstring(
            f'<get_tasks_response><task id="{task_id}"><name>Lab semanal</name>'
            f'<status>{self.status}</status><target id="tgt-1"><name>lab</name></target>'
            "</task></get_tasks_response>"
        )

    def get_target(self, target_id):
        return ET.fromstring(
            f'<get_targets_response><target id="{target_id}"><hosts>{self.hosts}</hosts>'
            "</target></get_targets_response>"
        )

    def start_task(self, task_id):
        self.started.append(task_id)
        return ET.fromstring(
            f"<start_task_response><report_id>{REPORT_ID}</report_id></start_task_response>"
        )

    def get_report(self, report_id, **kwargs):
        self.report_kwargs = kwargs
        return ET.fromstring(
            f'<get_reports_response><report id="{report_id}"><report id="{report_id}">'
            f"<scan_run_status>Done</scan_run_status><results>{self.results_xml}</results>"
            "</report></report></get_reports_response>"
        )


def factory_for(gmp: FakeGmp):
    @contextmanager
    def factory(settings):
        assert settings is SETTINGS
        yield gmp

    return factory


def result_xml(host, cves=("CVE-2024-6387",), severity="8.1", qod="80"):
    refs = "".join(f'<ref type="cve" id="{c.lower()}"/>' for c in cves)
    return (
        f'<result id="r-{host}"><name>OpenSSH regreSSHion</name>'
        f"<host>{host}<asset asset_id=\"a1\"/></host><port>22/tcp</port>"
        f'<nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>OpenSSH RCE</name>'
        f'<refs>{refs}<ref type="url" id="https://x"/></refs></nvt>'
        f"<severity>{severity}</severity><threat>High</threat>"
        f"<qod><value>{qod}</value></qod></result>"
    )


@pytest.mark.parametrize(
    ("spec", "target"),
    [
        ("192.168.10.25", "192.168.10.25"),
        ("192.168.10.25, 192.168.10.26", "192.168.10.0/24"),
        ("192.168.10.10-20", "192.168.10.0/24"),
        ("192.168.10.10-192.168.10.20", "192.168.10.0/27"),
        ("192.168.10.0/26", "192.168.10.0/24"),
    ],
)
def test_hosts_within_target(spec, target):
    assert ensure_hosts_within(spec, target)


@pytest.mark.parametrize(
    ("spec", "target", "message"),
    [
        ("192.168.10.25, 8.8.8.8", "192.168.10.0/24", "fuera del objetivo"),
        ("192.168.10.0/23", "192.168.10.0/24", "fuera del objetivo"),
        ("192.168.10.200-192.168.11.5", "192.168.10.0/24", "fuera del objetivo"),
        ("192.168.10.26", "192.168.10.25", "fuera del objetivo"),
        ("intranet.local", "192.168.10.0/24", "no puede verificarse"),
        ("192.168.10.20-10", "192.168.10.0/24", "no puede verificarse"),
        ("", "192.168.10.0/24", "no declara hosts"),
    ],
)
def test_hosts_outside_or_unverifiable_are_rejected(spec, target, message):
    with pytest.raises(GreenboneError, match=message):
        ensure_hosts_within(spec, target)


@pytest.mark.asyncio
async def test_start_task_verifies_gvmd_target_before_starting():
    gmp = FakeGmp(hosts="192.168.10.25")
    tool = GreenboneStartTaskTool(SETTINGS, mode="local", session_factory=factory_for(gmp))
    result = await tool.execute({"task_id": TASK_ID, "target": "192.168.10.25"})

    assert gmp.started == [TASK_ID]
    assert result["report_id"] == REPORT_ID
    assert result["scanned_hosts"] == ["192.168.10.25/32"]
    assert result["task_name"] == "Lab semanal"


@pytest.mark.asyncio
async def test_task_scanning_more_than_approved_never_starts():
    # The approval covered one host, but the gvmd task was edited to scan more.
    gmp = FakeGmp(hosts="192.168.10.25, 192.168.10.0/24")
    tool = GreenboneStartTaskTool(SETTINGS, mode="local", session_factory=factory_for(gmp))
    with pytest.raises(GreenboneError, match="fuera del objetivo"):
        await tool.execute({"task_id": TASK_ID, "target": "192.168.10.25"})
    assert gmp.started == []


@pytest.mark.asyncio
async def test_busy_or_missing_task_is_not_started():
    busy = FakeGmp(status="Running")
    tool = GreenboneStartTaskTool(SETTINGS, mode="local", session_factory=factory_for(busy))
    with pytest.raises(GreenboneError, match="en curso"):
        await tool.execute({"task_id": TASK_ID, "target": "192.168.10.25"})
    assert busy.started == []

    missing = FakeGmp()
    tool = GreenboneStartTaskTool(SETTINGS, mode="local", session_factory=factory_for(missing))
    with pytest.raises(GreenboneError, match="no existe"):
        await tool.execute(
            {"task_id": "2b5c1f0a-3c1e-4d7b-9f00-00000000dead", "target": "192.168.10.25"}
        )


@pytest.mark.asyncio
async def test_results_are_parsed_and_filtered_by_qod():
    gmp = FakeGmp(results_xml=result_xml("192.168.10.25") + result_xml("192.168.10.26", cves=()))
    tool = GreenboneResultsTool(SETTINGS, mode="local", session_factory=factory_for(gmp))
    result = await tool.execute({"report_id": REPORT_ID, "target": "192.168.10.0/24"})

    assert result["scan_run_status"] == "Done"
    assert result["total_results"] == 2
    first = result["results"][0]
    assert first == {
        "host": "192.168.10.25",
        "port": "22/tcp",
        "nvt_oid": "1.3.6.1.4.1.25623.1.0.1",
        "name": "OpenSSH regreSSHion",
        "severity": 8.1,
        "threat": "High",
        "qod": 80,
        "cve_ids": ["CVE-2024-6387"],
    }
    assert "min_qod=70" in gmp.report_kwargs["filter_string"]


@pytest.mark.asyncio
async def test_report_with_foreign_hosts_is_refused_without_naming_them():
    gmp = FakeGmp(results_xml=result_xml("192.168.10.25") + result_xml("10.20.30.40"))
    tool = GreenboneResultsTool(SETTINGS, mode="local", session_factory=factory_for(gmp))
    with pytest.raises(GreenboneError) as exc_info:
        await tool.execute({"report_id": REPORT_ID, "target": "192.168.10.0/24"})
    assert "10.20.30.40" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_unconfigured_and_mock_modes():
    with pytest.raises(GreenboneError, match="no está configurada"):
        await GreenboneStartTaskTool(None, mode="local").execute(
            {"task_id": TASK_ID, "target": "192.168.10.25"}
        )
    mock = await GreenboneStartTaskTool(None).execute(
        {"task_id": TASK_ID, "target": "192.168.10.25"}
    )
    assert mock["source"] == "simulated"


def test_arguments_are_strict():
    start = GreenboneStartTaskTool(None)
    results = GreenboneResultsTool(None)
    for bad in (
        {"task_id": "not-a-uuid", "target": "192.168.10.25"},
        {"task_id": TASK_ID, "target": "lab.local"},
        {"task_id": TASK_ID, "target": "192.168.10.25", "hosts": "8.8.8.8"},
    ):
        with pytest.raises(ValidationError):
            start.validate_arguments(bad)
    with pytest.raises(ValidationError):
        results.validate_arguments({"report_id": REPORT_ID, "target": "192.168.10.25", "task_id": TASK_ID})
    assert start.validate_arguments({"task_id": TASK_ID.upper(), "target": "192.168.10.0/24"}) == {
        "task_id": TASK_ID,
        "target": "192.168.10.0/24",
    }


def test_real_session_requires_a_connection_method():
    from app.tools.greenbone import open_gmp_session

    bare = GreenboneSettings(user="u", password=SecretStr("p"))
    with pytest.raises(GreenboneError, match="SOCKET_PATH o GREENBONE_HOST"):
        with open_gmp_session(bare):
            pass


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
  start_greenbone_task:
    enabled: true
    risk: high
    approval_required: true
  get_greenbone_results:
    enabled: true
    risk: low
    approval_required: false
"""


@pytest.mark.asyncio
async def test_broker_gates_start_with_approval_and_scope(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(POLICY, encoding="utf-8")
    broker = ToolBroker(
        policy=PolicyEngine(policy_file),
        tools=[GreenboneStartTaskTool(None), GreenboneResultsTool(None)],
        journal=InMemoryJournal(),
        budget_coordinator=InMemoryBudgetCoordinator(),
        tool_mode="mock",
    )

    def request(tool, arguments):
        return ToolRequest(
            request_id=uuid4(), requested_by="operador-test", tool=tool, arguments=arguments
        )

    start = await broker.execute(
        request("start_greenbone_task", {"task_id": TASK_ID, "target": "192.168.10.25"})
    )
    wide = await broker.execute(
        request("start_greenbone_task", {"task_id": TASK_ID, "target": "192.168.0.0/16"})
    )
    results = await broker.execute(
        request("get_greenbone_results", {"report_id": REPORT_ID, "target": "192.168.10.25"})
    )

    assert start.status == "approval_required"
    assert wide.status == "denied"
    assert results.status == "completed"
