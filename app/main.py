from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Response, status

from app.api.auth import require_operator
from app.api.models import ToolRequest, ToolRequestInput, ToolResponse
from app.core.auth import ApiKeyAuthenticator, Principal
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.settings import get_settings
from app.storage.postgres_journal import PostgresExecutionJournal
from app.tools.mock_inventory import MockInventoryTool


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.authenticator = ApiKeyAuthenticator.from_json(
        settings.api_credentials_json
    )
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
    auth_status = (
        "available" if app.state.authenticator.configured else "unconfigured"
    )
    try:
        await app.state.broker.journal.ping()
    except Exception:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "audit": "unavailable",
            "auth": auth_status,
        }
    if not app.state.authenticator.configured:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "audit": "available",
            "auth": "unconfigured",
        }
    return {"status": "ready", "audit": "available", "auth": "available"}


@app.post("/v1/tools/execute", response_model=ToolResponse)
async def execute_tool(
    request: ToolRequestInput,
    principal: Principal = Depends(require_operator),
) -> ToolResponse:
    verified_request = ToolRequest(
        **request.model_dump(),
        requested_by=principal.subject,
    )
    return await app.state.broker.execute(verified_request)
