from contextlib import asynccontextmanager
import json
import os

import httpx
import pytest

from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.llm.base import ModelCompletion
from app.main import app


OPERATOR_KEY = "operator-key-with-at-least-32-characters"
APPROVER_KEY = "approver-key-with-at-least-32-characters"
DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


class FinalAnswerLLM:
    async def chat_structured(self, model, messages, response_schema, **kwargs):
        return ModelCompletion(
            content=json.dumps({
                "thought": "No hace falta ninguna herramienta.",
                "action_type": "final_answer",
                "final_summary": "Respuesta de prueba.",
            }),
            model=model,
            prompt_eval_count=42,
            eval_count=17,
        )

    async def aclose(self):
        pass


def authenticator():
    return ApiKeyAuthenticator([
        ApiCredential(
            subject="trace-operator",
            role="operator",
            key_sha256=ApiKeyAuthenticator.hash_api_key(OPERATOR_KEY),
        ),
        ApiCredential(
            subject="trace-reviewer",
            role="approver",
            key_sha256=ApiKeyAuthenticator.hash_api_key(APPROVER_KEY),
        ),
    ])


@asynccontextmanager
async def api_client():
    async with app.router.lifespan_context(app):
        app.state.authenticator = authenticator()
        app.state.orchestrator.llm_client = FinalAnswerLLM()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def test_run_is_recorded_and_reviewable_only_by_approver():
    async with api_client() as client:
        run = await client.post(
            "/v1/orchestrator/run", json={"intent": "¿Qué es CyberCore?"}, headers=bearer(OPERATOR_KEY)
        )
        assert run.status_code == 200
        run_id = run.json()["run_id"]

        assert (await client.get("/v1/traces", headers=bearer(OPERATOR_KEY))).status_code == 403

        trace = await client.get(f"/v1/traces/{run_id}", headers=bearer(APPROVER_KEY))
        assert trace.status_code == 200
        body = trace.json()
        assert body["requested_by"] == "trace-operator"
        assert body["steps"][0]["prompt_tokens"] == 42
        assert "final_answer" in body["steps"][0]["raw_output"]

        review = await client.post(
            f"/v1/traces/{run_id}/reviews",
            json={"verdict": "approved", "notes": "Correcto"},
            headers=bearer(APPROVER_KEY),
        )
        assert review.status_code == 201
        assert review.json()["reviewer"] == "trace-reviewer"

        listed = await client.get("/v1/traces?limit=500", headers=bearer(APPROVER_KEY))
        summary = next(item for item in listed.json() if item["run_id"] == run_id)
        assert summary["latest_verdict"] == "approved"

        bad = await client.post(
            f"/v1/traces/{run_id}/reviews",
            json={"verdict": "approved", "corrections": {"9": {
                "thought": "t", "action_type": "final_answer", "final_summary": "s"}}},
            headers=bearer(APPROVER_KEY),
        )
        assert bad.status_code == 400

        missing = await client.get(
            "/v1/traces/00000000-0000-0000-0000-000000000000", headers=bearer(APPROVER_KEY)
        )
        assert missing.status_code == 404


class ScriptedLLM(FinalAnswerLLM):
    def __init__(self, actions):
        self.actions = list(actions)

    async def chat_structured(self, model, messages, response_schema, **kwargs):
        return ModelCompletion(content=json.dumps(self.actions.pop(0)), model=model)


async def test_trace_links_allowed_and_denied_tool_calls_to_audit_rows():
    async with api_client() as client:
        app.state.orchestrator.llm_client = ScriptedLLM([
            {"thought": "Inventario simulado.", "action_type": "call_tool",
             "tool": "get_mock_inventory", "arguments": {"target": "192.168.10.25"}},
            {"thought": "Pruebo fuera de alcance.", "action_type": "call_tool",
             "tool": "get_mock_inventory", "arguments": {"target": "8.8.8.8"}},
            {"thought": "Fin.", "action_type": "final_answer", "final_summary": "Ok."},
        ])
        run = await client.post(
            "/v1/orchestrator/run", json={"intent": "Inventario"}, headers=bearer(OPERATOR_KEY)
        )
        run_id = run.json()["run_id"]

        trace = await client.get(f"/v1/traces/{run_id}", headers=bearer(APPROVER_KEY))

        assert trace.status_code == 200
        allowed, denied, final = trace.json()["steps"]
        assert allowed["execution_id"] and denied["execution_id"]
        assert "denegada" in denied["observation"]
        assert final["execution_id"] is None
