import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.api.models import ToolRequest
from app.core.audit import AuditStoreError, ExecutionStart
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.tools.mock_inventory import MockInventoryTool


class RecordingJournal:
    def __init__(self, fail_begin: bool = False, fail_finish: bool = False):
        self.fail_begin = fail_begin
        self.fail_finish = fail_finish
        self.started: list[ExecutionStart] = []
        self.finished: list[tuple] = []

    async def begin(self, execution: ExecutionStart) -> None:
        if self.fail_begin:
            raise AuditStoreError("begin failed")
        self.started.append(execution)

    async def finish(self, execution_id, status, evidence=None, error=None) -> None:
        if self.fail_finish:
            raise AuditStoreError("finish failed")
        self.finished.append((execution_id, status, evidence, error))


class RecordingApprovalService:
    def __init__(self, result=False, error=None):
        self.result = result
        self.error = error
        self.consumed = []

    async def consume(
        self,
        token,
        requested_by,
        tool_name,
        arguments_sha256,
        request_id,
    ):
        self.consumed.append(
            (token, requested_by, tool_name, arguments_sha256, request_id)
        )
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def journal():
    return RecordingJournal()


@pytest.fixture
def broker(journal):
    return ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [MockInventoryTool()],
        journal=journal,
    )


@pytest.mark.asyncio
async def test_broker_returns_hashed_evidence(broker, journal):
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
    assert journal.started[0].status == "running"
    assert journal.started[0].normalized_arguments == {"target": "192.168.10.25"}
    assert journal.finished[0][1] == "completed"
    assert journal.finished[0][2] == response.evidence


@pytest.mark.asyncio
async def test_broker_denies_public_target(broker, journal):
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "1.1.1.1"},
            requested_by="test",
        )
    )
    assert response.status == "denied"
    assert response.evidence is None
    assert journal.started[0].status == "denied"
    assert journal.started[0].normalized_arguments == {"target": "1.1.1.1"}
    assert journal.finished == []


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
        ToolBroker(
            PolicyEngine("config/policy.yaml"),
            [RealAdapter()],
            journal=RecordingJournal(),
        )


def test_broker_rejects_live_mode_during_phase_zero():
    with pytest.raises(ValueError, match="Modo de herramientas inválido"):
        ToolBroker(
            PolicyEngine("config/policy.yaml"),
            [],
            journal=RecordingJournal(),
            tool_mode="live",
        )


def test_broker_rejects_duplicate_adapter_names():
    with pytest.raises(ValueError, match="nombres duplicados"):
        ToolBroker(
            PolicyEngine("config/policy.yaml"),
            [FakeAdapter(), FakeAdapter()],
            journal=RecordingJournal(),
        )


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
    broker = ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [adapter],
        journal=RecordingJournal(),
    )
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="test",
        )
    )

    assert response.status == "completed"
    assert adapter.observed == {"a": 0.0, "target": "192.168.10.25", "z": "é"}
    assert list(adapter.observed) == ["a", "target", "z"]


@pytest.mark.asyncio
async def test_audit_begin_failure_prevents_adapter_execution():
    adapter = RecordingAdapter()
    broker = ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [adapter],
        journal=RecordingJournal(fail_begin=True),
    )

    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="test",
        )
    )

    assert response.status == "failed"
    assert "auditoría durable" in response.error
    assert response.evidence is None
    assert adapter.observed is None


@pytest.mark.asyncio
async def test_audit_finish_failure_suppresses_evidence_response():
    adapter = RecordingAdapter()
    journal = RecordingJournal(fail_finish=True)
    broker = ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [adapter],
        journal=journal,
    )

    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="test",
        )
    )

    assert adapter.observed is not None
    assert journal.started[0].status == "running"
    assert response.status == "failed"
    assert response.evidence is None
    assert "cerrarse" in response.error


@pytest.mark.asyncio
async def test_denial_survives_audit_outage_without_execution():
    adapter = RecordingAdapter()
    broker = ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [adapter],
        journal=RecordingJournal(fail_begin=True),
    )

    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "8.8.8.8"},
            requested_by="test",
        )
    )

    assert response.status == "denied"
    assert response.error == "No se pudo persistir el registro de auditoría"
    assert adapter.observed is None


@pytest.mark.asyncio
async def test_adapter_timeout_fails_without_evidence():
    broker = ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [SlowAdapter()],
        journal=RecordingJournal(),
    )
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="test",
        )
    )
    assert response.status == "failed"
    assert response.evidence is None
    assert "límite" in response.error


@pytest.mark.asyncio
async def test_non_canonical_adapter_output_fails_without_leaking_details():
    broker = ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [NonFiniteResultAdapter()],
        journal=RecordingJournal(),
    )
    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="test",
        )
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
    broker = ToolBroker(
        PolicyEngine(policy_path),
        [FakeAdapter()],
        journal=RecordingJournal(),
    )

    first = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "8.8.8.8"},
            requested_by="test",
        )
    )
    second = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="test",
        )
    )

    assert first.status == "denied"
    assert second.status == "denied"
    assert "límite de solicitudes" in second.decision.reason


def approval_policy(tmp_path):
    policy_path = tmp_path / "approval-policy.yaml"
    config = yaml.safe_load(Path("config/policy.yaml").read_text(encoding="utf-8"))
    config["tools"]["get_mock_inventory"]["approval_required"] = True
    policy_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return PolicyEngine(policy_path)


@pytest.mark.asyncio
async def test_approval_is_consumed_with_canonical_argument_hash(tmp_path):
    adapter = RecordingAdapter()
    approvals = RecordingApprovalService(result=True)
    broker = ToolBroker(
        approval_policy(tmp_path),
        [adapter],
        journal=RecordingJournal(),
        approval_service=approvals,
    )
    request = ToolRequest(
        tool="get_mock_inventory",
        arguments={"target": "192.168.10.25"},
        requested_by="verified-operator",
        approval_token="approval-token-with-at-least-32-characters",
    )

    response = await broker.execute(request)

    assert response.status == "completed"
    consumed = approvals.consumed[0]
    assert consumed[0] == request.approval_token
    assert consumed[1] == "verified-operator"
    assert consumed[2] == "get_mock_inventory"
    assert consumed[3] == ToolBroker.arguments_sha256(adapter.observed)
    assert consumed[4] == request.request_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("approval_token", "approval_result", "approval_error"),
    [
        (None, False, None),
        ("invalid-token-with-at-least-32-characters", False, None),
        (
            "backend-error-token-with-at-least-32-characters",
            False,
            RuntimeError("backend unavailable"),
        ),
    ],
)
async def test_missing_invalid_or_unavailable_approval_never_executes(
    tmp_path,
    approval_token,
    approval_result,
    approval_error,
):
    adapter = RecordingAdapter()
    approvals = RecordingApprovalService(
        result=approval_result,
        error=approval_error,
    )
    broker = ToolBroker(
        approval_policy(tmp_path),
        [adapter],
        journal=RecordingJournal(),
        approval_service=approvals,
    )

    response = await broker.execute(
        ToolRequest(
            tool="get_mock_inventory",
            arguments={"target": "192.168.10.25"},
            requested_by="verified-operator",
            approval_token=approval_token,
        )
    )

    assert response.status == "approval_required"
    assert response.evidence is None
    assert adapter.observed is None
    assert len(approvals.consumed) == (0 if approval_token is None else 1)


def test_prepare_approval_uses_adapter_normalization(tmp_path):
    broker = ToolBroker(
        approval_policy(tmp_path),
        [RecordingAdapter()],
        journal=RecordingJournal(),
    )

    arguments, arguments_sha256 = broker.prepare_approval(
        "get_mock_inventory",
        {"target": "192.168.10.25"},
    )

    assert arguments == {"a": 0.0, "target": "192.168.10.25", "z": "é"}
    assert arguments_sha256 == ToolBroker.arguments_sha256(arguments)


def test_prepare_approval_rejects_tool_that_does_not_require_it():
    broker = ToolBroker(
        PolicyEngine("config/policy.yaml"),
        [FakeAdapter()],
        journal=RecordingJournal(),
    )

    with pytest.raises(ValueError, match="no requiere aprobación"):
        broker.prepare_approval(
            "get_mock_inventory",
            {"target": "192.168.10.25"},
        )
