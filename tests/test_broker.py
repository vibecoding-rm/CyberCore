import pytest

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
