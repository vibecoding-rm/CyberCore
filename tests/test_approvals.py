from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.approvals import ApprovalService


NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


class RecordingRepository:
    def __init__(self):
        self.created = []
        self.consumed = []

    async def create(self, grant):
        self.created.append(grant)
        return NOW + timedelta(seconds=grant.ttl_seconds)

    async def consume(
        self,
        token_sha256,
        requested_by,
        tool_name,
        arguments_sha256,
        request_id,
    ) -> bool:
        self.consumed.append(
            (
                token_sha256,
                requested_by,
                tool_name,
                arguments_sha256,
                request_id,
            )
        )
        return True

    async def ping(self) -> None:
        return None


def test_service_rejects_max_ttl_shorter_than_minimum():
    with pytest.raises(ValueError, match="al menos 60"):
        ApprovalService(RecordingRepository(), max_ttl_seconds=59)


@pytest.mark.asyncio
async def test_issue_persists_only_token_hash_and_exact_binding():
    repository = RecordingRepository()
    service = ApprovalService(repository, max_ttl_seconds=1800)

    issued = await service.issue(
        requested_by="operator-one",
        approved_by="approver-one",
        tool_name="approval_probe",
        normalized_arguments={"target": "192.168.10.25"},
        arguments_sha256="a" * 64,
        ttl_seconds=600,
    )

    grant = repository.created[0]
    assert grant.token_sha256 == service.hash_token(issued.approval_token)
    assert issued.approval_token not in repr(grant)
    assert grant.requested_by == "operator-one"
    assert grant.approved_by == "approver-one"
    assert grant.tool_name == "approval_probe"
    assert grant.normalized_arguments == {"target": "192.168.10.25"}
    assert grant.arguments_sha256 == "a" * 64
    assert grant.ttl_seconds == 600
    assert issued.expires_at == NOW + timedelta(seconds=600)


@pytest.mark.asyncio
async def test_consume_hashes_token_and_preserves_all_bindings():
    repository = RecordingRepository()
    service = ApprovalService(repository)
    request_id = uuid4()

    consumed = await service.consume(
        "approval-token-with-at-least-32-characters",
        "operator-one",
        "approval_probe",
        "b" * 64,
        request_id,
    )

    assert consumed is True
    stored = repository.consumed[0]
    assert stored[0] == service.hash_token(
        "approval-token-with-at-least-32-characters"
    )
    assert stored[1:] == (
        "operator-one",
        "approval_probe",
        "b" * 64,
        request_id,
    )


@pytest.mark.asyncio
async def test_short_or_oversized_token_is_rejected_without_storage_access():
    repository = RecordingRepository()
    service = ApprovalService(repository)

    assert await service.consume("short", "operator", "tool", "a" * 64, uuid4()) is False
    assert (
        await service.consume("x" * 501, "operator", "tool", "a" * 64, uuid4())
        is False
    )
    assert repository.consumed == []


@pytest.mark.asyncio
async def test_approver_cannot_approve_same_identity():
    repository = RecordingRepository()
    service = ApprovalService(repository)

    with pytest.raises(ValueError, match="propia ejecución"):
        await service.issue(
            requested_by="same-person",
            approved_by="same-person",
            tool_name="approval_probe",
            normalized_arguments={"target": "192.168.10.25"},
            arguments_sha256="c" * 64,
            ttl_seconds=600,
        )

    assert repository.created == []


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl_seconds", [59, 1801])
async def test_issue_enforces_ttl_bounds(ttl_seconds):
    repository = RecordingRepository()
    service = ApprovalService(repository, max_ttl_seconds=1800)

    with pytest.raises(ValueError, match="entre 60 y 1800"):
        await service.issue(
            requested_by="operator-one",
            approved_by="approver-one",
            tool_name="approval_probe",
            normalized_arguments={},
            arguments_sha256="d" * 64,
            ttl_seconds=ttl_seconds,
        )
