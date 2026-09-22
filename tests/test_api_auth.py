from contextlib import asynccontextmanager

import httpx
import pytest

from app.core.audit import ExecutionStart
from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.main import app


OPERATOR_KEY = "operator-key-with-at-least-32-characters"
VIEWER_KEY = "viewer-key-with-at-least-32-characters--"
pytestmark = pytest.mark.asyncio


class RecordingJournal:
    def __init__(self):
        self.started: list[ExecutionStart] = []
        self.finished: list[tuple] = []

    async def begin(self, execution: ExecutionStart) -> None:
        self.started.append(execution)

    async def finish(self, execution_id, status, evidence=None, error=None) -> None:
        self.finished.append((execution_id, status, evidence, error))

    async def ping(self) -> None:
        return None


def authenticator(subject, role, api_key):
    return ApiKeyAuthenticator(
        [
            ApiCredential(
                subject=subject,
                role=role,
                key_sha256=ApiKeyAuthenticator.hash_api_key(api_key),
            )
        ]
    )


def request_body():
    return {
        "tool": "get_mock_inventory",
        "arguments": {"target": "192.168.10.25"},
    }


@asynccontextmanager
async def api_client():
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            yield client


async def test_execute_fails_closed_when_authentication_is_unconfigured():
    async with api_client() as client:
        app.state.authenticator = ApiKeyAuthenticator([])
        response = await client.post("/v1/tools/execute", json=request_body())

    assert response.status_code == 503
    assert response.json()["detail"] == "La autenticación de la API no está configurada"


async def test_execute_does_not_distinguish_missing_and_invalid_keys():
    async with api_client() as client:
        app.state.authenticator = authenticator(
            "verified-operator", "operator", OPERATOR_KEY
        )
        missing = await client.post("/v1/tools/execute", json=request_body())
        invalid = await client.post(
            "/v1/tools/execute",
            json=request_body(),
            headers={"Authorization": "Bearer invalid-key-with-at-least-32-characters"},
        )

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert missing.json() == invalid.json()
    assert missing.headers["www-authenticate"] == "Bearer"


async def test_viewer_cannot_execute_tools():
    async with api_client() as client:
        app.state.authenticator = authenticator("verified-viewer", "viewer", VIEWER_KEY)
        response = await client.post(
            "/v1/tools/execute",
            json=request_body(),
            headers={"Authorization": f"Bearer {VIEWER_KEY}"},
        )

    assert response.status_code == 403


async def test_operator_identity_is_injected_into_durable_audit():
    journal = RecordingJournal()
    async with api_client() as client:
        app.state.authenticator = authenticator(
            "verified-operator", "operator", OPERATOR_KEY
        )
        app.state.broker.journal = journal
        response = await client.post(
            "/v1/tools/execute",
            json=request_body(),
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert journal.started[0].requested_by == "verified-operator"


async def test_client_cannot_spoof_requested_by():
    body = request_body() | {"requested_by": "spoofed-admin"}
    async with api_client() as client:
        app.state.authenticator = authenticator(
            "verified-operator", "operator", OPERATOR_KEY
        )
        response = await client.post(
            "/v1/tools/execute",
            json=body,
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
        )

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "extra_forbidden"


async def test_readiness_requires_audit_and_authentication():
    async with api_client() as client:
        app.state.broker.journal = RecordingJournal()
        app.state.authenticator = ApiKeyAuthenticator([])
        unconfigured = await client.get("/ready")
        app.state.authenticator = authenticator(
            "verified-operator", "operator", OPERATOR_KEY
        )
        ready = await client.get("/ready")

    assert unconfigured.status_code == 503
    assert unconfigured.json() == {
        "status": "not_ready",
        "audit": "available",
        "auth": "unconfigured",
    }
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ready",
        "audit": "available",
        "auth": "available",
    }
