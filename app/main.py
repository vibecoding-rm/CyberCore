from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Response, status

from app.api.auth import require_approver, require_operator
from app.api.models import (
    ApprovalCreateRequest,
    ApprovalResponse,
    InventoryAssessmentRequest,
    InventoryAssessmentResponse,
    ToolRequest,
    ToolRequestInput,
    ToolResponse,
)
from app.core.approvals import ApprovalService, ApprovalStoreError
from app.core.auth import ApiKeyAuthenticator, Principal
from app.core.evidence_analysis import EvidenceGapAnalyzer
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolBroker
from app.settings import get_settings
from app.storage.postgres_approvals import PostgresApprovalRepository
from app.storage.postgres_budgets import PostgresBudgetCoordinator
from app.storage.postgres_journal import PostgresExecutionJournal
from app.tools.mock_inventory import MockInventoryTool


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.authenticator = ApiKeyAuthenticator.from_json(
        settings.api_credentials_json
    )
    app.state.approval_service = ApprovalService(
        PostgresApprovalRepository(
            settings.database_url,
            settings.database_connect_timeout_seconds,
        ),
        max_ttl_seconds=settings.approval_max_ttl_seconds,
    )
    app.state.budget_coordinator = PostgresBudgetCoordinator(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        request_window_seconds=settings.budget_request_window_seconds,
        lease_grace_seconds=settings.budget_lease_grace_seconds,
        budget_key=settings.budget_key,
    )
    app.state.evidence_analyzer = EvidenceGapAnalyzer()
    app.state.broker = ToolBroker(
        policy=PolicyEngine(settings.policy_file),
        tools=[MockInventoryTool()],
        tool_mode=settings.tool_mode,
        journal=PostgresExecutionJournal(
            settings.database_url,
            settings.database_connect_timeout_seconds,
        ),
        budget_coordinator=app.state.budget_coordinator,
        approval_service=app.state.approval_service,
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
    approver_available = app.state.authenticator.has_role("approver")
    auth_status = (
        "available"
        if app.state.authenticator.has_role("operator")
        and (not app.state.broker.policy.requires_approver or approver_available)
        else "unconfigured"
    )
    try:
        await app.state.broker.journal.ping()
    except Exception:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "audit": "unavailable",
            "auth": auth_status,
            "approvals": "unknown",
            "budgets": "unknown",
        }
    try:
        await app.state.approval_service.ping()
    except Exception:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "audit": "available",
            "auth": auth_status,
            "approvals": "unavailable",
            "budgets": "unknown",
        }
    try:
        await app.state.budget_coordinator.ping()
    except Exception:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "audit": "available",
            "auth": auth_status,
            "approvals": "available",
            "budgets": "unavailable",
        }
    if auth_status != "available":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "audit": "available",
            "auth": "unconfigured",
            "approvals": "available",
            "budgets": "available",
        }
    return {
        "status": "ready",
        "audit": "available",
        "auth": "available",
        "approvals": "available",
        "budgets": "available",
    }


@app.post(
    "/v1/approvals",
    response_model=ApprovalResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_approval(
    request: ApprovalCreateRequest,
    principal: Principal = Depends(require_approver),
) -> ApprovalResponse:
    if not app.state.authenticator.has_identity(request.requested_by, "operator"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La identidad operadora solicitada no está configurada",
        )
    try:
        normalized_arguments, arguments_sha256 = app.state.broker.prepare_approval(
            request.tool,
            request.arguments,
        )
        issued = await app.state.approval_service.issue(
            requested_by=request.requested_by,
            approved_by=principal.subject,
            tool_name=request.tool,
            normalized_arguments=normalized_arguments,
            arguments_sha256=arguments_sha256,
            ttl_seconds=request.expires_in_seconds,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ApprovalStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El almacén de aprobaciones no está disponible",
        ) from exc

    return ApprovalResponse(
        approval_id=issued.approval_id,
        approval_token=issued.approval_token,
        requested_by=issued.requested_by,
        approved_by=issued.approved_by,
        tool=issued.tool_name,
        arguments_sha256=issued.arguments_sha256,
        expires_at=issued.expires_at,
    )


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


@app.post(
    "/v1/analysis/inventory",
    response_model=InventoryAssessmentResponse,
)
async def analyze_inventory(
    request: InventoryAssessmentRequest,
    principal: Principal = Depends(require_operator),
) -> InventoryAssessmentResponse:
    inventory = await app.state.broker.execute(
        ToolRequest(
            request_id=request.request_id,
            tool="get_mock_inventory",
            arguments={"target": request.target},
            requested_by=principal.subject,
        )
    )
    assessment = None
    if inventory.status == "completed" and inventory.evidence is not None:
        assessment = app.state.evidence_analyzer.analyze(
            inventory.evidence,
            request.vulnerability_id,
        )
    return InventoryAssessmentResponse(
        inventory=inventory,
        assessment=assessment,
    )
