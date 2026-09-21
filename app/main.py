from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.models import ToolRequest, ToolResponse
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.settings import get_settings
from app.tools.mock_inventory import MockInventoryTool


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.broker = ToolBroker(
        policy=PolicyEngine(settings.policy_file),
        tools=[MockInventoryTool()],
        tool_mode=settings.tool_mode,
    )
    yield


app = FastAPI(
    title="CyberCore Starter",
    version="0.1.0",
    description="Broker defensivo con alcance y evidencia.",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "mode": get_settings().tool_mode}


@app.post("/v1/tools/execute", response_model=ToolResponse)
async def execute_tool(request: ToolRequest) -> ToolResponse:
    return await app.state.broker.execute(request)
