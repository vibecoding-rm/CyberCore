from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Response, status

from app.api.auth import require_approver, require_operator
from app.api.models import (
    ApprovalCreateRequest,
    ApprovalResponse,
    EvidenceAnalysisRequest,
    EvidenceAssessment,
    InventoryAssessmentRequest,
    InventoryAssessmentResponse,
    ToolRequest,
    ToolRequestInput,
    ToolResponse,
    VersionMatchRequest,
)
from app.agent.models import AgentRunResult, OrchestratorRunRequest
from app.agent.orchestrator import CyberCoreOrchestrator
from app.core.approvals import ApprovalService, ApprovalStoreError
from app.core.audit import AuditStoreError, EvidenceIntegrityError
from app.core.auth import ApiKeyAuthenticator, Principal
from app.core.evidence_analysis import EvidenceGapAnalyzer
from app.core.policy import PolicyEngine
from app.core.tool_broker import ToolAdapter, ToolBroker
from app.intelligence.matching import VersionMatch, VulnerabilityMatcher
from app.llm.factory import create_chat_client
from app.settings import get_settings
from app.storage.postgres_approvals import PostgresApprovalRepository
from app.storage.postgres_assets import PostgresAssetRepository
from app.storage.postgres_budgets import PostgresBudgetCoordinator
from app.storage.postgres_journal import PostgresExecutionJournal
from app.storage.postgres_vulnerabilities import (
    PostgresVulnerabilityRepository,
    VulnerabilityStoreError,
)
from app.tools.mock_inventory import MockInventoryTool
from app.tools.nmap import NmapDiscoverHostsTool, NmapInspectServicesTool
from app.tools.nuclei import NucleiSafeTool
from app.tools.nuclei_catalog import NucleiTemplateCatalog
from app.tools.greenbone import (
    GreenboneResultsTool,
    GreenboneSettings,
    GreenboneStartTaskTool,
)
from app.tools.wazuh import WazuhInventoryTool, WazuhSettings


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
    app.state.asset_repository = PostgresAssetRepository(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
    )
    app.state.vulnerability_repository = PostgresVulnerabilityRepository(
        database_url=settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
    )
    app.state.evidence_analyzer = EvidenceGapAnalyzer()
    app.state.vulnerability_matcher = VulnerabilityMatcher(
        app.state.vulnerability_repository
    )

    tools: list[ToolAdapter] = [
        MockInventoryTool(),
        NmapDiscoverHostsTool(mode=settings.tool_mode),
        NmapInspectServicesTool(mode=settings.tool_mode),
        NucleiSafeTool(
            NucleiTemplateCatalog.from_yaml(
                settings.nuclei_allowlist_file,
                settings.nuclei_templates_dir,
            ),
            mode=settings.tool_mode,
        ),
        WazuhInventoryTool(_wazuh_settings(settings), mode=settings.tool_mode),
        GreenboneStartTaskTool(_greenbone_settings(settings), mode=settings.tool_mode),
        GreenboneResultsTool(_greenbone_settings(settings), mode=settings.tool_mode),
    ]
    app.state.evidence_store = PostgresExecutionJournal(
        settings.database_url,
        settings.database_connect_timeout_seconds,
    )
    app.state.broker = ToolBroker(
        policy=PolicyEngine(settings.policy_file),
        tools=tools,
        tool_mode=settings.tool_mode,
        journal=app.state.evidence_store,
        budget_coordinator=app.state.budget_coordinator,
        approval_service=app.state.approval_service,
    )
    app.state.llm_client = create_chat_client(settings)
    app.state.orchestrator = CyberCoreOrchestrator(
        llm_client=app.state.llm_client,
        model_name=settings.orchestrator_model,
        broker=app.state.broker,
        asset_repo=app.state.asset_repository,
        vuln_repo=app.state.vulnerability_repository,
        analyzer=app.state.evidence_analyzer,
    )
    yield
    await app.state.llm_client.aclose()


def _wazuh_settings(settings) -> WazuhSettings | None:
    if not settings.wazuh_api_url:
        return None
    return WazuhSettings(
        base_url=settings.wazuh_api_url,
        user=settings.wazuh_api_user,
        password=settings.wazuh_api_password,
        verify_tls=settings.wazuh_verify_tls,
        ca_bundle=settings.wazuh_ca_bundle or None,
    )


def _greenbone_settings(settings) -> GreenboneSettings | None:
    if not settings.greenbone_user or not (
        settings.greenbone_socket_path or settings.greenbone_host
    ):
        return None
    return GreenboneSettings(
        user=settings.greenbone_user,
        password=settings.greenbone_password,
        socket_path=settings.greenbone_socket_path or None,
        host=settings.greenbone_host or None,
        port=settings.greenbone_port,
        cafile=settings.greenbone_cafile or None,
    )


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
    response = await app.state.broker.execute(verified_request)
    if response.status == "completed" and response.evidence is not None:
        try:
            await app.state.asset_repository.record_evidence(response.evidence)
        except Exception:
            pass
    return response


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
        try:
            await app.state.asset_repository.record_evidence(inventory.evidence)
        except Exception:
            pass

        vuln_info = None
        version_matches: list[VersionMatch] = []
        if request.vulnerability_id:
            try:
                vuln_info = await app.state.vulnerability_repository.get_vulnerability(
                    request.vulnerability_id
                )
            except Exception:
                pass
            version_matches = await _match_observed_services(
                request.vulnerability_id,
                inventory.evidence.data,
            )

        assessment = app.state.evidence_analyzer.analyze(
            inventory.evidence,
            request.vulnerability_id,
            vulnerability_info=vuln_info,
            version_matches=version_matches,
        )
    return InventoryAssessmentResponse(
        inventory=inventory,
        assessment=assessment,
    )


INVENTORY_SOURCES = {"inspect_services", "get_mock_inventory"}


@app.post("/v1/analysis/evidence", response_model=EvidenceAssessment)
async def analyze_sealed_evidence(
    request: EvidenceAnalysisRequest,
    principal: Principal = Depends(require_operator),
) -> EvidenceAssessment:
    """Assess evidence previously sealed by the broker, never client-supplied data."""
    inventory = await _load_evidence(request.inventory_evidence_id)
    if inventory.source not in INVENTORY_SOURCES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"La evidencia {inventory.evidence_id} no es un inventario de servicios",
        )
    validation = [await _load_evidence(eid) for eid in request.validation_evidence_ids]

    try:
        vuln_info = await app.state.vulnerability_repository.get_vulnerability(
            request.vulnerability_id
        )
    except VulnerabilityStoreError:
        vuln_info = None
    version_matches = await _match_observed_services(
        request.vulnerability_id,
        inventory.data,
    )
    return app.state.evidence_analyzer.analyze(
        inventory,
        request.vulnerability_id,
        vulnerability_info=vuln_info,
        version_matches=version_matches,
        validation_evidence=validation,
    )


async def _load_evidence(evidence_id: str):
    try:
        evidence = await app.state.evidence_store.get_evidence(evidence_id)
    except EvidenceIntegrityError as exc:
        # Never analyze evidence whose integrity cannot be proven.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except AuditStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El almacén de evidencia no está disponible",
        ) from exc
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidencia no encontrada o de una ejecución no completada: {evidence_id}",
        )
    return evidence


@app.get("/v1/assets")
async def list_assets(
    principal: Principal = Depends(require_operator),
) -> list[dict]:
    return await app.state.asset_repository.list_assets()


@app.get("/v1/assets/{address}")
async def get_asset_by_address(
    address: str,
    principal: Principal = Depends(require_operator),
) -> dict:
    asset = await app.state.asset_repository.get_asset_by_address(address)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Activo no encontrado para la dirección: {address}",
        )
    return asset


@app.get("/v1/vulnerabilities")
async def list_vulnerabilities(
    limit: int = 50,
    kev_only: bool = False,
    principal: Principal = Depends(require_operator),
) -> list[dict]:
    return await app.state.vulnerability_repository.list_vulnerabilities(
        limit=limit,
        kev_only=kev_only,
    )


@app.get("/v1/vulnerabilities/{vulnerability_id}")
async def get_vulnerability(
    vulnerability_id: str,
    principal: Principal = Depends(require_operator),
) -> dict:
    vuln = await app.state.vulnerability_repository.get_vulnerability(vulnerability_id)
    if vuln is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerabilidad {vulnerability_id} no encontrada en la base local",
        )
    return vuln


@app.get("/v1/vulnerabilities/{vulnerability_id}/ranges")
async def get_vulnerability_ranges(
    vulnerability_id: str,
    principal: Principal = Depends(require_operator),
) -> list[dict]:
    try:
        return await app.state.vulnerability_repository.get_affected_ranges(vulnerability_id)
    except VulnerabilityStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El almacén de vulnerabilidades no está disponible",
        ) from exc


@app.post("/v1/vulnerabilities/match", response_model=VersionMatch)
async def match_vulnerability_version(
    request: VersionMatchRequest,
    principal: Principal = Depends(require_operator),
) -> VersionMatch:
    matcher: VulnerabilityMatcher = app.state.vulnerability_matcher
    try:
        if request.cpe is not None:
            return await matcher.match_cpe(request.vulnerability_id, request.cpe)
        return await matcher.match_package(
            request.vulnerability_id,
            request.ecosystem,
            request.package,
            request.version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    except VulnerabilityStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El almacén de vulnerabilidades no está disponible",
        ) from exc


async def _match_observed_services(
    vulnerability_id: str,
    inventory_data: dict,
) -> list[VersionMatch]:
    """Evaluate every open service that carries a CPE fingerprint."""
    matches: list[VersionMatch] = []
    for service in inventory_data.get("services") or []:
        if not isinstance(service, dict) or service.get("state") != "open":
            continue
        cpe = service.get("cpe")
        if not isinstance(cpe, str) or not cpe:
            continue
        try:
            matches.append(
                await app.state.vulnerability_matcher.match_cpe(vulnerability_id, cpe)
            )
        except (ValueError, VulnerabilityStoreError):
            continue
    return matches


@app.post(
    "/v1/orchestrator/run",
    response_model=AgentRunResult,
)
async def run_orchestrator(
    request: OrchestratorRunRequest,
    principal: Principal = Depends(require_operator),
) -> AgentRunResult:
    return await app.state.orchestrator.run(
        operator_intent=request.intent,
        requested_by=principal.subject,
        approval_token=request.approval_token,
    )


