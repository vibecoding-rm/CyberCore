from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, status

from app.api.models import ToolRequest, ToolResponse
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.settings import get_settings
from app.storage.postgres_journal import PostgresExecutionJournal
from app.tools.mock_inventory import MockInventoryTool


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.broker = ToolBroker(
        policy=PolicyEngine(settings.policy_file),
        tools=[MockInventoryTool()],
        tool_mode=settings.tool_mode,
        journal=PostgresExecutionJournal(
            settings.database_url,
            settings.database_connect_timeout_seconds,
        ),
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


@app.get("/ready")
async def ready(response: Response) -> dict[str, str]:
    try:
        await app.state.broker.journal.ping()
    except Exception:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "audit": "unavailable"}
    return {"status": "ready", "audit": "available"}


@app.post("/v1/tools/execute", response_model=ToolResponse)
async def execute_tool(request: ToolRequest) -> ToolResponse:
    return await app.state.broker.execute(request)
