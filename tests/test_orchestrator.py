import json
from uuid import uuid4
import pytest

from app.agent.models import AgentThoughtAndAction
from app.agent.orchestrator import CyberCoreOrchestrator
from app.api.models import Evidence, PolicyDecision, ToolRequest, ToolResponse
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.llm.ollama import ModelCompletion
from app.tools.nmap import NmapDiscoverHostsTool, NmapInspectServicesTool


class MockLLMClient:
    def __init__(self, responses: list[dict]):
        self.responses = responses
        self.call_count = 0

    async def chat_structured(self, model, messages, response_schema, **kwargs):
        if self.call_count >= len(self.responses):
            return ModelCompletion(
                content=json.dumps({
                    "thought": "No more responses programmed",
                    "action_type": "final_answer",
                    "final_summary": "Auto-concluded due to end of programmed responses",
                }),
                model=model,
            )
        resp = self.responses[self.call_count]
        self.call_count += 1
        return ModelCompletion(
            content=json.dumps(resp),
            model=model,
        )


class FakeJournal:
    async def begin(self, execution):
        pass

    async def finish(self, execution_id, status, evidence=None, error=None):
        pass

    async def ping(self):
        pass


class FakeBudget:
    async def reserve_request(self, request_id, max_requests):
        return "accepted"

    async def acquire_slot(self, request_id, max_parallel, timeout):
        from app.core.budgets import ConcurrencyLease
        return ConcurrencyLease(lease_id=uuid4(), request_id=request_id)

    async def release_slot(self, lease):
        pass

    async def ping(self):
        pass


@pytest.fixture
def broker(tmp_path):
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
    p_file = tmp_path / "policy.yaml"
    p_file.write_text(policy_content, encoding="utf-8")
    return ToolBroker(
        policy=PolicyEngine(p_file),
        tools=[
            NmapDiscoverHostsTool(mode="mock"),
            NmapInspectServicesTool(mode="mock"),
        ],
        journal=FakeJournal(),
        budget_coordinator=FakeBudget(),
        tool_mode="mock",
    )


@pytest.mark.asyncio
async def test_orchestrator_immediate_final_answer(broker):
    mock_llm = MockLLMClient([
        {
            "thought": "El usuario hace una pregunta conceptual que no requiere herramientas de red.",
            "action_type": "final_answer",
            "final_summary": "CyberCore es un sistema defensivo que opera bajo estricto control de alcance.",
        }
    ])

    orchestrator = CyberCoreOrchestrator(
        llm_client=mock_llm,
        model_name="mock-model",
        broker=broker,
    )

    result = await orchestrator.run("¿Qué es CyberCore?")

    assert result.status == "completed"
    assert "CyberCore es un sistema defensivo" in result.final_report
    assert len(result.steps) == 1
    assert result.steps[0].action_type == "final_answer"


@pytest.mark.asyncio
async def test_orchestrator_executes_tool_then_finishes(broker):
    mock_llm = MockLLMClient([
        {
            "thought": "Debo escanear la subred autorizada para descubrir hosts.",
            "action_type": "call_tool",
            "tool": "discover_hosts",
            "arguments": {"target": "192.168.10.0/24"},
        },
        {
            "thought": "Se descubrieron 2 hosts activos. Ya puedo informar al operador.",
            "action_type": "final_answer",
            "final_summary": "Se detectaron 2 hosts activos en la subred 192.168.10.0/24.",
        },
    ])

    orchestrator = CyberCoreOrchestrator(
        llm_client=mock_llm,
        model_name="mock-model",
        broker=broker,
    )

    result = await orchestrator.run("Descubre los hosts en 192.168.10.0/24")

    assert result.status == "completed"
    assert len(result.steps) == 2
    assert result.steps[0].action_type == "call_tool"
    assert result.steps[0].tool == "discover_hosts"
    assert result.steps[1].action_type == "final_answer"
    assert len(result.discovered_assets) == 2


@pytest.mark.asyncio
async def test_orchestrator_halts_at_approval_required(broker):
    # inspect_services requires approval in our policy
    mock_llm = MockLLMClient([
        {
            "thought": "Voy a inspeccionar los puertos del host 192.168.10.15.",
            "action_type": "call_tool",
            "tool": "inspect_services",
            "arguments": {"target": "192.168.10.15", "ports": [22, 80]},
        }
    ])

    orchestrator = CyberCoreOrchestrator(
        llm_client=mock_llm,
        model_name="mock-model",
        broker=broker,
    )

    result = await orchestrator.run("Inspecciona puertos de 192.168.10.15")

    assert result.status == "approval_required"
    assert result.pending_approval is not None
    assert result.pending_approval["tool"] == "inspect_services"
    assert result.pending_approval["risk"] == "medium"
    assert "aprobación" in result.final_report


@pytest.mark.asyncio
async def test_orchestrator_handles_out_of_scope_denial(broker):
    mock_llm = MockLLMClient([
        {
            "thought": "El usuario pidió escanear 8.8.8.8, voy a intentar ejecutarlo.",
            "action_type": "call_tool",
            "tool": "discover_hosts",
            "arguments": {"target": "8.8.8.8"},
        },
        {
            "thought": "La política denegó el objetivo por estar fuera de alcance. Informo al operador.",
            "action_type": "final_answer",
            "final_summary": "No se puede escanear 8.8.8.8 porque está fuera del alcance autorizado.",
        },
    ])

    orchestrator = CyberCoreOrchestrator(
        llm_client=mock_llm,
        model_name="mock-model",
        broker=broker,
    )

    result = await orchestrator.run("Escanea 8.8.8.8")

    assert result.status == "completed"
    assert len(result.steps) == 2
    assert "denegada por política" in result.steps[0].observation
    assert "fuera del alcance" in result.final_report
