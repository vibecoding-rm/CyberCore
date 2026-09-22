import pytest
from uuid import uuid4

from app.api.models import ToolRequest
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.tools.nmap import NmapDiscoverHostsTool, NmapInspectServicesTool


from app.core.audit import ExecutionStart
from app.core.budgets import ConcurrencyLease


class InMemoryJournal:
    def __init__(self):
        self.started = []
        self.finished = []

    async def begin(self, execution: ExecutionStart) -> None:
        self.started.append(execution)

    async def finish(self, execution_id, status, evidence=None, error=None) -> None:
        self.finished.append((execution_id, status, evidence, error))

    async def ping(self) -> None:
        pass


class InMemoryBudgetCoordinator:
    def __init__(self):
        self.reservations = []
        self.acquired = []
        self.released = []

    async def reserve_request(self, request_id, max_requests):
        self.reservations.append(request_id)
        return "accepted"

    async def acquire_slot(
        self,
        request_id,
        max_parallel,
        execution_timeout_seconds,
    ):
        lease = ConcurrencyLease(lease_id=uuid4(), request_id=request_id)
        self.acquired.append(lease)
        return lease

    async def release_slot(self, lease):
        self.released.append(lease)

    async def ping(self):
        pass


@pytest.mark.asyncio
async def test_tool_broker_executes_mock_nmap_discover(tmp_path):
    policy_content = """
version: 1
scope:
  allowed_networks:
    - 192.168.10.0/24
    - 127.0.0.0/8
  denied_networks:
    - 0.0.0.0/8
  allow_hostnames: false
budgets:
  max_targets_per_request: 256
  max_duration_seconds: 300
  max_parallel_jobs: 2
  max_requests_per_hour: 30
tools:
  discover_hosts:
    enabled: true
    risk: low
    approval_required: false
evidence:
  hash_algorithm: sha256
  append_only: true
  retain_raw_output: true
llm:
  may_request_tools: true
  may_execute_shell: false
  may_change_policy: false
  may_self_approve: false
"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_content, encoding="utf-8")

    tool = NmapDiscoverHostsTool(mode="mock")
    broker = ToolBroker(
        policy=PolicyEngine(policy_file),
        tools=[tool],
        journal=InMemoryJournal(),
        budget_coordinator=InMemoryBudgetCoordinator(),
        tool_mode="mock",
    )

    request = ToolRequest(
        request_id=uuid4(),
        requested_by="operador-test",
        tool="discover_hosts",
        arguments={"target": "192.168.10.0/24"},
    )

    response = await broker.execute(request)

    assert response.status == "completed"
    assert response.decision.allowed is True
    assert response.evidence is not None
    assert response.evidence.source == "discover_hosts"
    assert response.evidence.data["total_hosts_up"] == 2
    assert len(response.evidence.sha256) == 64


@pytest.mark.asyncio
async def test_tool_broker_blocks_out_of_scope_target(tmp_path):
    policy_content = """
version: 1
scope:
  allowed_networks:
    - 192.168.10.0/24
  denied_networks:
    - 0.0.0.0/8
  allow_hostnames: false
budgets:
  max_targets_per_request: 256
  max_duration_seconds: 300
  max_parallel_jobs: 2
  max_requests_per_hour: 30
tools:
  discover_hosts:
    enabled: true
    risk: low
    approval_required: false
evidence:
  hash_algorithm: sha256
  append_only: true
  retain_raw_output: true
llm:
  may_request_tools: true
  may_execute_shell: false
  may_change_policy: false
  may_self_approve: false
"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_content, encoding="utf-8")

    tool = NmapDiscoverHostsTool(mode="mock")
    broker = ToolBroker(
        policy=PolicyEngine(policy_file),
        tools=[tool],
        journal=InMemoryJournal(),
        budget_coordinator=InMemoryBudgetCoordinator(),
        tool_mode="mock",
    )

    # 8.8.8.8 is outside allowed_networks
    request = ToolRequest(
        request_id=uuid4(),
        requested_by="operador-test",
        tool="discover_hosts",
        arguments={"target": "8.8.8.8"},
    )

    response = await broker.execute(request)

    assert response.status == "denied"
    assert response.decision.allowed is False
    assert "fuera del alcance" in response.decision.reason
    assert response.evidence is None


@pytest.mark.asyncio
async def test_tool_broker_executes_mock_nmap_inspect_services(tmp_path):
    policy_content = """
version: 1
scope:
  allowed_networks:
    - 192.168.10.0/24
  denied_networks:
    - 0.0.0.0/8
  allow_hostnames: false
budgets:
  max_targets_per_request: 256
  max_duration_seconds: 300
  max_parallel_jobs: 2
  max_requests_per_hour: 30
tools:
  inspect_services:
    enabled: true
    risk: medium
    approval_required: false
evidence:
  hash_algorithm: sha256
  append_only: true
  retain_raw_output: true
llm:
  may_request_tools: true
  may_execute_shell: false
  may_change_policy: false
  may_self_approve: false
"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_content, encoding="utf-8")

    tool = NmapInspectServicesTool(mode="mock")
    broker = ToolBroker(
        policy=PolicyEngine(policy_file),
        tools=[tool],
        journal=InMemoryJournal(),
        budget_coordinator=InMemoryBudgetCoordinator(),
        tool_mode="mock",
    )

    request = ToolRequest(
        request_id=uuid4(),
        requested_by="operador-test",
        tool="inspect_services",
        arguments={"target": "192.168.10.15", "ports": [22, 80]},
    )

    response = await broker.execute(request)

    assert response.status == "completed"
    assert response.decision.allowed is True
    assert response.evidence is not None
    assert response.evidence.source == "inspect_services"
    assert len(response.evidence.data["services"]) == 2
    assert response.evidence.data["services"][0]["port"] == 22


@pytest.mark.asyncio
async def test_tool_broker_requires_approval_for_inspect_services(tmp_path):
    policy_content = """
version: 1
scope:
  allowed_networks:
    - 192.168.10.0/24
  denied_networks:
    - 0.0.0.0/8
  allow_hostnames: false
budgets:
  max_targets_per_request: 256
  max_duration_seconds: 300
  max_parallel_jobs: 2
  max_requests_per_hour: 30
tools:
  inspect_services:
    enabled: true
    risk: medium
    approval_required: true
evidence:
  hash_algorithm: sha256
  append_only: true
  retain_raw_output: true
llm:
  may_request_tools: true
  may_execute_shell: false
  may_change_policy: false
  may_self_approve: false
"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_content, encoding="utf-8")

    tool = NmapInspectServicesTool(mode="mock")
    broker = ToolBroker(
        policy=PolicyEngine(policy_file),
        tools=[tool],
        journal=InMemoryJournal(),
        budget_coordinator=InMemoryBudgetCoordinator(),
        tool_mode="mock",
    )

    # Request without approval_token
    request = ToolRequest(
        request_id=uuid4(),
        requested_by="operador-test",
        tool="inspect_services",
        arguments={"target": "192.168.10.15", "ports": [22, 80]},
    )

    response = await broker.execute(request)

    assert response.status == "approval_required"
    assert response.decision.allowed is False
    assert response.evidence is None

