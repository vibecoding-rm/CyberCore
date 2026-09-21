import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.api.models import ToolRequest
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.tools.mock_inventory import MockInventoryTool


@pytest.fixture
def broker():
    return ToolBroker(PolicyEngine("config/policy.yaml"), [MockInventoryTool()])


@pytest.mark.asyncio
async def test_broker_returns_hashed_evidence(broker):
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="test",
        )
    )
    assert response.status == "completed"
    assert response.evidence is not None
    assert len(response.evidence.sha256) == 64
    assert response.evidence.data["source"] == "simulated"


@pytest.mark.asyncio
async def test_broker_denies_public_target(broker):
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "1.1.1.1"},
            requested_by="test",
        )
    )
    assert response.status == "denied"
    assert response.evidence is None


@pytest.mark.asyncio
async def test_broker_denies_extra_arguments(broker):
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25", "raw_flags": "--script exploit"},
            requested_by="test",
        )
    )
    assert response.status == "denied"
    assert "raw_flags" in response.decision.reason


@pytest.mark.asyncio
async def test_broker_denies_non_string_target(broker):
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": 3232238105},
            requested_by="test",
        )
    )
    assert response.status == "denied"


class FakeAdapter:
    name = "get_mock_inventory"
    mode = "mock"
    timeout_seconds = 1.0

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return arguments

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True}


class RealAdapter(FakeAdapter):
    mode = "real"


class SlowAdapter(FakeAdapter):
    timeout_seconds = 0.001

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(0.05)
        return {"ok": True}


class NonFiniteResultAdapter(FakeAdapter):
    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"score": float("nan")}


class RecordingAdapter(FakeAdapter):
    observed: dict[str, Any] | None = None

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"z": "e\u0301", "target": arguments["target"], "a": -0.0}

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self.observed = arguments
        return {"ok": True}


def test_broker_rejects_real_adapter_in_mock_mode():
    with pytest.raises(ValueError, match="sólo permite adaptadores simulados"):
        ToolBroker(PolicyEngine("config/policy.yaml"), [RealAdapter()])


def test_broker_rejects_live_mode_during_phase_zero():
    with pytest.raises(ValueError, match="Modo de herramientas inválido"):
        ToolBroker(PolicyEngine("config/policy.yaml"), [], tool_mode="live")


def test_broker_rejects_duplicate_adapter_names():
    with pytest.raises(ValueError, match="nombres duplicados"):
        ToolBroker(PolicyEngine("config/policy.yaml"), [FakeAdapter(), FakeAdapter()])


def test_canonical_json_is_stable_and_normalizes_unicode():
    first = ToolBroker.canonical_json({"z": "e\u0301", "a": -0.0})
    second = ToolBroker.canonical_json({"a": 0.0, "z": "é"})
    assert first == second
    assert first == '{"a":0.0,"z":"é"}'.encode("utf-8")


def test_canonical_json_rejects_unicode_key_collisions():
    with pytest.raises(ValueError, match="normalización JSON canónica"):
        ToolBroker.canonical_json({"é": 1, "e\u0301": 2})


def test_canonical_json_rejects_non_finite_numbers():
    with pytest.raises(ValueError, match="normalización JSON canónica"):
        ToolBroker.canonical_json({"score": float("nan")})


@pytest.mark.asyncio
async def test_broker_executes_only_canonical_arguments():
    adapter = RecordingAdapter()
    broker = ToolBroker(PolicyEngine("config/policy.yaml"), [adapter])
    response = await broker.execute(
        ToolRequest(tool="get_mock_inventory", arguments={"target": "192.168.10.25"})
    )

    assert response.status == "completed"
    assert adapter.observed == {"a": 0.0, "target": "192.168.10.25", "z": "é"}
    assert list(adapter.observed) == ["a", "target", "z"]


@pytest.mark.asyncio
async def test_adapter_timeout_fails_without_evidence():
    broker = ToolBroker(PolicyEngine("config/policy.yaml"), [SlowAdapter()])
    response = await broker.execute(
        ToolRequest(tool="get_mock_inventory", arguments={"target": "192.168.10.25"})
    )
    assert response.status == "failed"
    assert response.evidence is None
    assert "límite" in response.error


@pytest.mark.asyncio
async def test_non_canonical_adapter_output_fails_without_leaking_details():
    broker = ToolBroker(PolicyEngine("config/policy.yaml"), [NonFiniteResultAdapter()])
    response = await broker.execute(
        ToolRequest(tool="get_mock_inventory", arguments={"target": "192.168.10.25"})
    )
    assert response.status == "failed"
    assert response.evidence is None
    assert response.error == "El adaptador falló de forma controlada"


@pytest.mark.asyncio
async def test_hourly_budget_counts_denied_requests(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    config = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    config["budgets"]["max_requests_per_hour"] = 1
    policy_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    broker = ToolBroker(PolicyEngine(policy_path), [FakeAdapter()])

    first = await broker.execute(
        ToolRequest(tool="get_mock_inventory", arguments={"target": "8.8.8.8"})
    )
    second = await broker.execute(
        ToolRequest(tool="get_mock_inventory", arguments={"target": "192.168.10.25"})
    )

    assert first.status == "denied"
    assert second.status == "denied"
    assert "límite de solicitudes" in second.decision.reason
