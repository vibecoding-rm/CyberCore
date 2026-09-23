import base64
import json
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.api.models import ToolRequest
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.tools.wazuh import WazuhError, WazuhInventoryTool, WazuhSettings
from tests.test_broker_nmap_integration import InMemoryBudgetCoordinator, InMemoryJournal

TARGET = "192.168.10.25"
PASSWORD = "s3cret-wazuh-password"
TOKEN = "eyJhbGciOiJFUzUxMiJ9.payload.signature"
SETTINGS = WazuhSettings(
    base_url="https://wazuh.test:55000",
    user="cybercore-ro",
    password=SecretStr(PASSWORD),
)


def ok(items, total=None):
    return httpx.Response(
        200,
        json={
            "data": {"affected_items": items, "total_affected_items": total or len(items)},
            "error": 0,
        },
    )


def make_handler(agents=None, packages_total=3, seen=None):
    agents = agents if agents is not None else [
        {"id": "001", "name": "web-01", "ip": TARGET, "status": "active"}
    ]
    all_packages = [
        {"name": f"pkg-{i}", "version": f"1.{i}", "vendor": "v", "architecture": "amd64",
         "format": "deb", "source": "src", "agent_id": "001"}
        for i in range(packages_total)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        path = request.url.path
        if path == "/security/user/authenticate":
            expected = base64.b64encode(f"cybercore-ro:{PASSWORD}".encode()).decode()
            if request.headers.get("authorization") != f"Basic {expected}":
                return httpx.Response(401)
            return httpx.Response(200, text=TOKEN)
        if request.headers.get("authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401)
        if path == "/agents":
            return ok(agents)
        if path == "/syscollector/001/os":
            return ok([{"os": {"name": "Ubuntu", "version": "24.04", "platform": "ubuntu"},
                        "hostname": "web-01", "architecture": "x86_64"}])
        if path == "/syscollector/001/packages":
            offset = int(request.url.params["offset"])
            limit = int(request.url.params["limit"])
            return ok(all_packages[offset:offset + limit], total=packages_total)
        if path == "/syscollector/001/ports":
            return ok([{"local": {"ip": "0.0.0.0", "port": 22}, "protocol": "tcp",
                        "process": "sshd", "pid": 812, "state": "listening"}])
        return httpx.Response(404)

    return handler


def tool_with(handler) -> tuple[WazuhInventoryTool, httpx.AsyncClient]:
    client = httpx.AsyncClient(
        base_url="https://wazuh.test:55000", transport=httpx.MockTransport(handler)
    )
    return WazuhInventoryTool(SETTINGS, mode="local", http_client=client), client


@pytest.mark.asyncio
async def test_collects_inventory_and_never_leaks_credentials():
    seen: list[httpx.Request] = []
    tool, client = tool_with(make_handler(packages_total=1203, seen=seen))
    try:
        result = await tool.execute({"target": TARGET})
    finally:
        await client.aclose()

    assert result["source"] == "wazuh"
    assert result["agent"]["id"] == "001"
    assert result["operating_system"]["name"] == "Ubuntu"
    assert result["total_packages"] == 1203 and result["packages_truncated"] is False
    assert result["listening_ports"][0] == {
        "port": 22, "local_ip": "0.0.0.0", "protocol": "tcp", "process": "sshd", "pid": 812
    }
    serialized = json.dumps(result)
    assert PASSWORD not in serialized and TOKEN not in serialized
    # Basic credentials only travel to the authentication endpoint.
    basic = [r for r in seen if r.headers.get("authorization", "").startswith("Basic")]
    assert [r.url.path for r in basic] == ["/security/user/authenticate"]
    assert seen[1].url.params["ip"] == TARGET


@pytest.mark.asyncio
async def test_package_collection_is_capped(monkeypatch):
    monkeypatch.setattr("app.tools.wazuh.MAX_PACKAGES", 600)
    tool, client = tool_with(make_handler(packages_total=2000))
    try:
        result = await tool.execute({"target": TARGET})
    finally:
        await client.aclose()
    assert result["total_packages"] == 600 and result["packages_truncated"] is True


@pytest.mark.asyncio
async def test_agents_for_other_ips_are_filtered_out():
    # A server that ignores the ip filter returns every agent.
    agents = [
        {"id": "002", "name": "db-01", "ip": "192.168.10.30", "status": "active"},
        {"id": "003", "name": "hr-laptop", "ip": "192.168.10.31", "status": "active"},
    ]
    tool, client = tool_with(make_handler(agents=agents))
    try:
        result = await tool.execute({"target": TARGET})
    finally:
        await client.aclose()
    assert result["agent"] is None
    assert result["candidate_agents"] == []  # other hosts are never disclosed
    assert "ningún agente" in result["notice"]


@pytest.mark.asyncio
async def test_duplicate_agents_are_not_picked_arbitrarily():
    agents = [
        {"id": "001", "name": "web-01", "ip": TARGET, "status": "active"},
        {"id": "004", "name": "web-01-old", "ip": TARGET, "status": "disconnected"},
    ]
    tool, client = tool_with(make_handler(agents=agents))
    try:
        result = await tool.execute({"target": TARGET})
    finally:
        await client.aclose()
    assert result["agent"] is None and len(result["candidate_agents"]) == 2
    assert result["packages"] == []


@pytest.mark.asyncio
async def test_invalid_agent_id_is_rejected():
    agents = [{"id": "../../security/users", "name": "x", "ip": TARGET}]
    tool, client = tool_with(make_handler(agents=agents))
    try:
        with pytest.raises(WazuhError, match="identificador"):
            await tool.execute({"target": TARGET})
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_auth_failure_is_sanitized():
    def handler(_request):
        return httpx.Response(401, text=f"bad password {PASSWORD}")

    tool, client = tool_with(handler)
    try:
        with pytest.raises(WazuhError) as exc_info:
            await tool.execute({"target": TARGET})
    finally:
        await client.aclose()
    assert "HTTP 401" in str(exc_info.value) and PASSWORD not in str(exc_info.value)


@pytest.mark.asyncio
async def test_api_level_error_is_reported():
    def handler(request):
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text=TOKEN)
        return httpx.Response(200, json={"data": {}, "error": 1, "message": "internal"})

    tool, client = tool_with(handler)
    try:
        with pytest.raises(WazuhError):
            await tool.execute({"target": TARGET})
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_unconfigured_local_mode_fails_and_mock_needs_nothing():
    with pytest.raises(WazuhError, match="no está configurada"):
        await WazuhInventoryTool(None, mode="local").execute({"target": TARGET})
    mock = await WazuhInventoryTool(None).execute({"target": TARGET})
    assert mock["source"] == "simulated" and mock["total_packages"] == 3


def test_arguments_are_strict():
    tool = WazuhInventoryTool(None)
    for bad in ({"target": "wazuh.local"}, {"target": TARGET, "agent_id": "001"}, {}):
        with pytest.raises(ValidationError):
            tool.validate_arguments(bad)


def test_settings_verify_prefers_ca_bundle():
    assert SETTINGS.verify is True
    custom = SETTINGS.model_copy(update={"ca_bundle": "/etc/wazuh/root-ca.pem"})
    assert custom.verify == "/etc/wazuh/root-ca.pem"
    assert PASSWORD not in repr(SETTINGS)


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
  get_wazuh_inventory:
    enabled: true
    risk: low
    approval_required: false
"""


@pytest.mark.asyncio
async def test_broker_runs_read_only_inventory_in_scope_only(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(POLICY, encoding="utf-8")
    broker = ToolBroker(
        policy=PolicyEngine(policy_file),
        tools=[WazuhInventoryTool(None)],
        journal=InMemoryJournal(),
        budget_coordinator=InMemoryBudgetCoordinator(),
        tool_mode="mock",
    )

    def request(target):
        return ToolRequest(
            request_id=uuid4(),
            requested_by="operador-test",
            tool="get_wazuh_inventory",
            arguments={"target": target},
        )

    allowed = await broker.execute(request(TARGET))
    public = await broker.execute(request("8.8.8.8"))

    assert allowed.status == "completed"
    assert allowed.evidence is not None and allowed.evidence.target == TARGET
    assert public.status == "denied"
