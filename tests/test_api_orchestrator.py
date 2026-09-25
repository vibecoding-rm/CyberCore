from contextlib import asynccontextmanager
import json
import os
import httpx
import pytest

from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.llm.ollama import ModelCompletion
from app.main import app


OPERATOR_KEY = "operator-key-with-at-least-32-characters"
DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


class MockLLMClient:
    async def chat_structured(self, model, messages, response_schema, **kwargs):
        return ModelCompletion(
            content=json.dumps({
                "thought": "El operador solicitó un inventario básico. Ya dispongo de la información.",
                "action_type": "final_answer",
                "final_summary": "Operación de prueba del orquestador completada con éxito.",
            }),
            model=model,
        )

    async def aclose(self):
        pass


def operator_authenticator():
    return ApiKeyAuthenticator(
        [
            ApiCredential(
                subject="test-operator",
                role="operator",
                key_sha256=ApiKeyAuthenticator.hash_api_key(OPERATOR_KEY),
            )
        ]
    )


@asynccontextmanager
async def api_client():
    async with app.router.lifespan_context(app):
        app.state.authenticator = operator_authenticator()
        app.state.orchestrator.llm_client = MockLLMClient()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
        ) as client:
            yield client


async def test_orchestrator_api_endpoint():
    async with api_client() as client:
        response = await client.post(
            "/v1/orchestrator/run",
            json={
                "intent": "¿Qué servicios están autorizados?",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert "completada con éxito" in data["final_report"]
        assert len(data["steps"]) == 1
        assert data["steps"][0]["action_type"] == "final_answer"
