import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from app.agent.models import (
    AgentRunResult,
    AgentStep,
    AgentThoughtAndAction,
)
from app.agent.prompts import build_agent_step_prompt
from app.agent.traces import AgentTrace, TraceRecorder, TraceStep
from app.api.models import ToolRequest
from app.core.evidence_analysis import EvidenceGapAnalyzer
from app.core.tool_broker import ToolBroker
from app.llm.base import ChatClient
from app.storage.postgres_assets import PostgresAssetRepository
from app.storage.postgres_vulnerabilities import PostgresVulnerabilityRepository

logger = logging.getLogger(__name__)


class CyberCoreOrchestrator:
    def __init__(
        self,
        llm_client: ChatClient,
        model_name: str,
        broker: ToolBroker,
        asset_repo: PostgresAssetRepository | None = None,
        vuln_repo: PostgresVulnerabilityRepository | None = None,
        analyzer: EvidenceGapAnalyzer | None = None,
        max_steps: int = 5,
        trace_recorder: TraceRecorder | None = None,
    ):
        if max_steps < 1 or max_steps > 15:
            raise ValueError("max_steps debe estar entre 1 y 15")
        self.llm_client = llm_client
        self.model_name = model_name
        self.broker = broker
        self.asset_repo = asset_repo
        self.vuln_repo = vuln_repo
        self.analyzer = analyzer or EvidenceGapAnalyzer()
        self.max_steps = max_steps
        self.trace_recorder = trace_recorder

    async def run(
        self,
        operator_intent: str,
        requested_by: str = "operator",
        approval_token: str | None = None,
    ) -> AgentRunResult:
        run_id = uuid4()
        started_at = datetime.now(timezone.utc)
        trace_steps: list[TraceStep] = []
        result = await self._run(
            run_id, operator_intent, requested_by, approval_token, trace_steps
        )
        if self.trace_recorder is not None:
            await self._record_trace(result, requested_by, started_at, trace_steps)
        return result

    async def _record_trace(
        self,
        result: AgentRunResult,
        requested_by: str,
        started_at: datetime,
        trace_steps: list[TraceStep],
    ) -> None:
        # Every model call yields exactly one AgentStep with the same number.
        observations = {step.step_number: step.observation for step in result.steps}
        for trace_step in trace_steps:
            trace_step.observation = observations.get(trace_step.step_number)
        trace = AgentTrace(
            run_id=result.run_id,
            requested_by=requested_by,
            operator_intent=result.operator_intent,
            model=self.model_name,
            status=result.status,
            final_report=result.final_report,
            response_schema=AgentThoughtAndAction.model_json_schema(),
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            steps=trace_steps,
        )
        try:
            await self.trace_recorder.save(trace)
        except Exception:
            # A trace is training material, not a control: losing one must not
            # hide the result of a run whose tool calls are already audited.
            logger.warning("No se pudo guardar la traza %s", result.run_id, exc_info=True)

    async def _run(
        self,
        run_id: UUID,
        operator_intent: str,
        requested_by: str,
        approval_token: str | None,
        trace_steps: list[TraceStep],
    ) -> AgentRunResult:
        steps: list[AgentStep] = []
        discovered_assets: list[dict[str, Any]] = []

        logger.info(f"Iniciando orquestación {run_id} para: {operator_intent}")

        for step_idx in range(1, self.max_steps + 1):
            messages = build_agent_step_prompt(
                step_number=step_idx,
                operator_intent=operator_intent,
                previous_steps=[s.model_dump() for s in steps],
            )

            trace_step = TraceStep(step_number=step_idx, messages=messages)
            trace_steps.append(trace_step)
            try:
                completion = await self.llm_client.chat_structured(
                    model=self.model_name,
                    messages=messages,
                    response_schema=AgentThoughtAndAction.model_json_schema(),
                    think=False,
                    num_predict=256,
                    num_ctx=2048,
                )
                trace_step.raw_output = completion.content
                trace_step.prompt_tokens = completion.prompt_eval_count
                trace_step.generated_tokens = completion.eval_count
                action_data = json.loads(completion.content)
                action = AgentThoughtAndAction.model_validate(action_data)
            except Exception as exc:
                logger.error(f"Error al obtener razonamiento del LLM en paso {step_idx}: {exc}")
                trace_step.error = str(exc)
                steps.append(
                    AgentStep(
                        step_number=step_idx,
                        thought="Error en inferencia o formato JSON del modelo.",
                        action_type="error",
                        observation=f"Fallo en la llamada estructurada: {str(exc)}",
                    )
                )
                return AgentRunResult(
                    run_id=run_id,
                    operator_intent=operator_intent,
                    status="error",
                    steps=steps,
                    discovered_assets=discovered_assets,
                    final_report=f"La orquestación falló en el paso {step_idx}: {str(exc)}",
                )

            # Case A: Model decides to finish
            if action.action_type == "final_answer":
                report = action.final_summary or action.thought
                steps.append(
                    AgentStep(
                        step_number=step_idx,
                        thought=action.thought,
                        action_type="final_answer",
                        observation="El orquestador completó el análisis defensivo.",
                    )
                )
                return AgentRunResult(
                    run_id=run_id,
                    operator_intent=operator_intent,
                    status="completed",
                    steps=steps,
                    discovered_assets=discovered_assets,
                    final_report=report,
                )

            # Case B: Model calls a tool
            tool_name = (action.tool or "").strip()
            tool_args = action.arguments or {}

            if not tool_name:
                obs = "Error: action_type='call_tool' pero no se especificó 'tool'."
                steps.append(
                    AgentStep(
                        step_number=step_idx,
                        thought=action.thought,
                        action_type="call_tool",
                        observation=obs,
                    )
                )
                continue

            tool_req = ToolRequest(
                request_id=uuid4(),
                requested_by=requested_by,
                tool=tool_name,
                arguments=tool_args,
                approval_token=approval_token,
            )

            trace_step.execution_id = tool_req.request_id
            tool_resp = await self.broker.execute(tool_req)

            # Handle approval required
            if tool_resp.status == "approval_required":
                obs = (
                    f"Acción detenida: La herramienta '{tool_name}' requiere aprobación previa "
                    f"(riesgo {tool_resp.decision.risk}). Solicita token a un supervisor."
                )
                steps.append(
                    AgentStep(
                        step_number=step_idx,
                        thought=action.thought,
                        action_type="call_tool",
                        tool=tool_name,
                        arguments=tool_args,
                        observation=obs,
                    )
                )
                return AgentRunResult(
                    run_id=run_id,
                    operator_intent=operator_intent,
                    status="approval_required",
                    steps=steps,
                    discovered_assets=discovered_assets,
                    pending_approval={
                        "tool": tool_name,
                        "arguments": tool_args,
                        "risk": tool_resp.decision.risk,
                    },
                    final_report=(
                        f"La acción '{tool_name}' sobre {tool_args.get('target', 'el objetivo')} "
                        f"requiere aprobación formal de un supervisor debido a su nivel de riesgo ({tool_resp.decision.risk})."
                    ),
                )

            # Handle denial (e.g. out of scope)
            if tool_resp.status == "denied":
                obs = f"Ejecución denegada por política de alcance: {tool_resp.decision.reason}"
                steps.append(
                    AgentStep(
                        step_number=step_idx,
                        thought=action.thought,
                        action_type="call_tool",
                        tool=tool_name,
                        arguments=tool_args,
                        observation=obs,
                    )
                )
                continue

            # Handle failure
            if tool_resp.status == "failed":
                obs = f"Fallo al ejecutar herramienta '{tool_name}': {tool_resp.error}"
                steps.append(
                    AgentStep(
                        step_number=step_idx,
                        thought=action.thought,
                        action_type="call_tool",
                        tool=tool_name,
                        arguments=tool_args,
                        observation=obs,
                    )
                )
                continue

            # Handle completed
            evidence = tool_resp.evidence
            evidence_sha = evidence.sha256 if evidence else None

            if evidence and self.asset_repo:
                try:
                    await self.asset_repo.record_evidence(evidence)
                except Exception as asset_err:
                    logger.warning(f"No se pudo guardar activo en BD: {asset_err}")

            obs = f"Herramienta '{tool_name}' ejecutada con éxito. Hash de evidencia: {evidence_sha[:16] if evidence_sha else 'N/A'}...\n"
            if tool_name == "discover_hosts" and evidence:
                hosts = evidence.data.get("hosts", [])
                obs += f"Hosts activos descubiertos: {len(hosts)}\n"
                for h in hosts:
                    # Nmap adapters emit "address"; "ip" kept for older evidence.
                    ip = h.get("address") or h.get("ip")
                    obs += f" - IP: {ip} | Hostname: {h.get('hostname') or 'desconocido'}\n"
                    discovered_assets.append(h)

            elif tool_name in ("inspect_services", "get_mock_inventory") and evidence:
                services = evidence.data.get("services", [])
                obs += f"Servicios observados en {evidence.target}:\n"
                for s in services:
                    port = s.get("port")
                    proto = s.get("protocol", "tcp")
                    svc_name = s.get("service") or s.get("service_name") or "unknown"
                    product = s.get("product") or "desconocido"
                    ver = s.get("version") or "desconocida"
                    obs += f" - Puerto {port}/{proto}: {svc_name} (producto: {product}, versión: {ver})\n"

                    # Look up any known KEV/EPSS intelligence if product or CVE mentioned
                    if self.vuln_repo and product != "desconocido":
                        obs += f"   [Defensa] Recuerda: Se requiere advisory del proveedor para contrastar la versión {ver}.\n"

            steps.append(
                AgentStep(
                    step_number=step_idx,
                    thought=action.thought,
                    action_type="call_tool",
                    tool=tool_name,
                    arguments=tool_args,
                    observation=obs,
                    evidence_sha256=evidence_sha,
                )
            )

        # Max steps reached without final_answer
        return AgentRunResult(
            run_id=run_id,
            operator_intent=operator_intent,
            status="completed",
            steps=steps,
            discovered_assets=discovered_assets,
            final_report=(
                "Se alcanzó el límite máximo de pasos de orquestación defensiva. "
                "Revisa la evidencia de los pasos ejecutados."
            ),
        )
