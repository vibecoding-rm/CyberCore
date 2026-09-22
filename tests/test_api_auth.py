from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from app.core.approvals import ApprovalService
from app.core.audit import ExecutionStart
from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.main import app


OPERATOR_KEY = "operator-key-with-at-least-32-characters"
VIEWER_KEY = "viewer-key-with-at-least-32-characters--"
APPROVER_KEY = "approver-key-with-at-least-32-characters"
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


class RecordingApprovalRepository:
    def __init__(self):
        self.grants = []
        self.consumed = set()

    async def create(self, grant):
        self.grants.append(grant)
        return datetime.now(timezone.utc) + timedelta(seconds=grant.ttl_seconds)

    async def consume(
        self,
        token_sha256,
        requested_by,
        tool_name,
        arguments_sha256,
        request_id,
    ) -> bool:
        for grant in self.grants:
            if (
                grant.token_sha256 == token_sha256
                and grant.requested_by == requested_by
                and grant.tool_name == tool_name
                and grant.arguments_sha256 == arguments_sha256
                and grant.approval_id not in self.consumed
            ):
                self.consumed.add(grant.approval_id)
                return True
        return False

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


def operator_and_approver_authenticator():
    return ApiKeyAuthenticator(
        [
            ApiCredential(
                subject="verified-operator",
                role="operator",
                key_sha256=ApiKeyAuthenticator.hash_api_key(OPERATOR_KEY),
            ),
            ApiCredential(
                subject="verified-approver",
                role="approver",
                key_sha256=ApiKeyAuthenticator.hash_api_key(APPROVER_KEY),
            ),
        ]
    )


class ApprovalAdapter:
    name = "get_mock_inventory"
    mode = "mock"
    timeout_seconds = 1.0

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"target": arguments["target"]}

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"target": arguments["target"], "approved": True}


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
        app.state.approval_service = ApprovalService(RecordingApprovalRepository())
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
        "approvals": "available",
    }
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ready",
        "audit": "available",
        "auth": "available",
        "approvals": "available",
    }


async def test_approver_issues_exact_single_use_token_for_operator(tmp_path):
    config = yaml.safe_load(
        Path("config/policy.yaml").read_text(encoding="utf-8")
    )
    config["tools"]["get_mock_inventory"]["approval_required"] = True
    policy_path = tmp_path / "approval-policy.yaml"
    policy_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    repository = RecordingApprovalRepository()
    approval_service = ApprovalService(repository)
    journal = RecordingJournal()

    async with api_client() as client:
        app.state.authenticator = operator_and_approver_authenticator()
        app.state.approval_service = approval_service
        app.state.broker = ToolBroker(
            PolicyEngine(policy_path),
            [ApprovalAdapter()],
            journal=journal,
            approval_service=approval_service,
        )
        approval_response = await client.post(
            "/v1/approvals",
            headers={"Authorization": f"Bearer {APPROVER_KEY}"},
            json={
                "requested_by": "verified-operator",
                "tool": "get_mock_inventory",
                "arguments": {"target": "192.168.10.25"},
                "expires_in_seconds": 600,
            },
        )
        approval = approval_response.json()
        execution_body = request_body() | {
            "approval_token": approval["approval_token"]
        }
        first = await client.post(
            "/v1/tools/execute",
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
            json=execution_body,
        )
        replay = await client.post(
            "/v1/tools/execute",
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
            json=execution_body,
        )

    assert approval_response.status_code == 201
    assert approval["requested_by"] == "verified-operator"
    assert approval["approved_by"] == "verified-approver"
    assert approval["approval_token"] not in repr(repository.grants[0])
    assert first.status_code == 200
    assert first.json()["status"] == "completed"
    assert replay.status_code == 200
    assert replay.json()["status"] == "approval_required"
    assert len(repository.consumed) == 1


async def test_operator_cannot_issue_approval():
    async with api_client() as client:
        app.state.authenticator = operator_and_approver_authenticator()
        response = await client.post(
            "/v1/approvals",
            headers={"Authorization": f"Bearer {OPERATOR_KEY}"},
            json={
                "requested_by": "verified-operator",
                "tool": "get_mock_inventory",
                "arguments": {"target": "192.168.10.25"},
            },
        )

    assert response.status_code == 403
