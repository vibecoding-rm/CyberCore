import asyncio
import hashlib
import json
import logging
from copy import deepcopy
from math import isfinite
from typing import Any
from unicodedata import normalize

from pydantic import ValidationError

from app.api.models import Evidence, PolicyDecision, ToolRequest, ToolResponse
from app.core.approvals import ApprovalService
from app.core.audit import ExecutionJournal, ExecutionStart
from app.core.budgets import BudgetCoordinator, ConcurrencyLease
from app.core.policy import PolicyEngine
from app.tools.base import ToolAdapter


logger = logging.getLogger(__name__)


class ToolBroker:
    def __init__(
        self,
        policy: PolicyEngine,
        tools: list[ToolAdapter],
        journal: ExecutionJournal,
        budget_coordinator: BudgetCoordinator,
        approval_service: ApprovalService | None = None,
        tool_mode: str = "mock",
    ):
        if tool_mode not in {"mock", "local"}:
            raise ValueError(f"Modo de herramientas inválido: {tool_mode}")

        names = [tool.name for tool in tools]
        if len(names) != len(set(names)):
            raise ValueError("No se permiten adaptadores con nombres duplicados")
        if tool_mode == "mock" and any(tool.mode != "mock" for tool in tools):
            raise ValueError("TOOL_MODE=mock sólo permite adaptadores simulados")

        self.policy = policy
        self.tools = {tool.name: tool for tool in tools}
        self.journal = journal
        self.budget_coordinator = budget_coordinator
        self.approval_service = approval_service
        self.tool_mode = tool_mode

    async def execute(self, request: ToolRequest) -> ToolResponse:
        original_arguments = deepcopy(request.arguments)

        try:
            reservation = await self.budget_coordinator.reserve_request(
                request.request_id,
                self.policy.budgets.max_requests_per_hour,
            )
        except Exception:
            logger.exception(
                "No se pudo reservar el presupuesto de %s", request.request_id
            )
            decision = self.policy.deny(
                request.tool,
                "El coordinador de presupuestos no está disponible",
            )
            response = ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="Ejecución cancelada: el presupuesto compartido no está disponible",
            )
            return await self._record_terminal(
                request, original_arguments, None, response
            )

        if reservation == "duplicate":
            decision = self.policy.deny(
                request.tool,
                "El request_id ya fue utilizado",
            )
            return ToolResponse(
                request_id=request.request_id,
                status="denied",
                decision=decision,
            )

        if reservation == "limit_reached":
            decision = self.policy.deny(
                request.tool,
                "Se alcanzó el límite de solicitudes por hora",
            )
            response = ToolResponse(
                request_id=request.request_id,
                status="denied",
                decision=decision,
            )
            return await self._record_terminal(
                request, original_arguments, None, response
            )

        if reservation != "accepted":
            logger.error(
                "El coordinador devolvió una reserva inválida para %s: %r",
                request.request_id,
                reservation,
            )
            decision = self.policy.deny(
                request.tool,
                "El coordinador de presupuestos devolvió un estado inválido",
            )
            response = ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="Ejecución cancelada: no se pudo confirmar el presupuesto",
            )
            return await self._record_terminal(
                request, original_arguments, None, response
            )

        tool = self.tools.get(request.tool)
        if tool is None:
            decision = self.policy.evaluate(
                request.tool,
                request.arguments,
            )
            if not decision.allowed:
                status = "approval_required" if decision.approval_required else "denied"
                response = ToolResponse(
                    request_id=request.request_id,
                    status=status,
                    decision=decision,
                )
            else:
                response = ToolResponse(
                    request_id=request.request_id,
                    status="failed",
                    decision=decision,
                    error="El adaptador permitido no está cargado",
                )
            return await self._record_terminal(
                request, original_arguments, None, response
            )

        try:
            normalized_arguments = tool.validate_arguments(request.arguments)
            canonical_arguments = self.canonicalize_arguments(normalized_arguments)
        except (ValidationError, ValueError, TypeError) as exc:
            decision = self.policy.deny(
                request.tool,
                f"Argumentos inválidos para la herramienta: {self._validation_summary(exc)}",
            )
            response = ToolResponse(
                request_id=request.request_id,
                status="denied",
                decision=decision,
            )
            return await self._record_terminal(
                request, original_arguments, None, response
            )

        timeout = min(
            float(tool.timeout_seconds), self.policy.budgets.max_duration_seconds
        )
        if not isfinite(timeout) or timeout <= 0:
            decision = self.policy.deny(
                request.tool, "El timeout del adaptador no es válido"
            )
            response = ToolResponse(
                request_id=request.request_id,
                status="denied",
                decision=decision,
            )
            return await self._record_terminal(
                request,
                original_arguments,
                canonical_arguments,
                response,
            )

        pre_decision = self.policy.evaluate(request.tool, canonical_arguments)
        if not pre_decision.allowed and (
            not pre_decision.approval_required or not request.approval_token
        ):
            status = (
                "approval_required" if pre_decision.approval_required else "denied"
            )
            response = ToolResponse(
                request_id=request.request_id,
                status=status,
                decision=pre_decision,
            )
            return await self._record_terminal(
                request,
                original_arguments,
                canonical_arguments,
                response,
            )

        try:
            lease = await self.budget_coordinator.acquire_slot(
                request.request_id,
                self.policy.budgets.max_parallel_jobs,
                timeout,
            )
        except Exception:
            logger.exception(
                "No se pudo adquirir capacidad para %s", request.request_id
            )
            decision = self.policy.deny(
                request.tool,
                "El coordinador de presupuestos no está disponible",
            )
            response = ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="Ejecución cancelada: la capacidad compartida no está disponible",
            )
            return await self._record_terminal(
                request,
                original_arguments,
                canonical_arguments,
                response,
            )

        if lease is None:
            decision = self.policy.deny(
                request.tool,
                "Se alcanzó el límite de ejecuciones paralelas",
            )
            response = ToolResponse(
                request_id=request.request_id,
                status="denied",
                decision=decision,
            )
            return await self._record_terminal(
                request,
                original_arguments,
                canonical_arguments,
                response,
            )

        try:
            return await self._execute_with_lease(
                request,
                original_arguments,
                canonical_arguments,
                timeout,
            )
        finally:
            await self._release_lease(lease)

    async def _execute_with_lease(
        self,
        request: ToolRequest,
        original_arguments: dict[str, Any],
        canonical_arguments: dict[str, Any],
        timeout: float,
    ) -> ToolResponse:
        decision = await self._authorize(request, canonical_arguments)
        if not decision.allowed:
            status = "approval_required" if decision.approval_required else "denied"
            response = ToolResponse(
                request_id=request.request_id,
                status=status,
                decision=decision,
            )
            return await self._record_terminal(
                request,
                original_arguments,
                canonical_arguments,
                response,
            )

        try:
            await self.journal.begin(
                ExecutionStart(
                    execution_id=request.request_id,
                    requested_by=request.requested_by,
                    tool_name=request.tool,
                    original_arguments=original_arguments,
                    normalized_arguments=canonical_arguments,
                    policy_decision=decision,
                    status="running",
                )
            )
        except Exception:
            logger.exception(
                "No se pudo iniciar la auditoría de %s", request.request_id
            )
            return ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="Ejecución cancelada: la auditoría durable no está disponible",
            )

        response = await self._execute_adapter(
            request,
            canonical_arguments,
            decision,
            timeout,
        )

        try:
            await self.journal.finish(
                request.request_id,
                response.status,
                response.evidence,
                response.error,
            )
        except Exception:
            logger.exception("No se pudo cerrar la auditoría de %s", request.request_id)
            return ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="La ejecución terminó, pero no pudo cerrarse la auditoría durable",
            )

        return response

    async def _release_lease(self, lease: ConcurrencyLease) -> None:
        try:
            await self.budget_coordinator.release_slot(lease)
        except Exception:
            logger.exception(
                "No se pudo liberar el lease %s de %s",
                lease.lease_id,
                lease.request_id,
            )

    def prepare_approval(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        tool = self.tools.get(tool_name)
        if tool is None:
            raise ValueError("La herramienta no tiene un adaptador cargado")

        try:
            normalized = tool.validate_arguments(arguments)
            canonical_arguments = self.canonicalize_arguments(normalized)
        except (ValidationError, ValueError, TypeError) as exc:
            raise ValueError(
                f"Argumentos inválidos: {self._validation_summary(exc)}"
            ) from exc

        decision = self.policy.evaluate(tool_name, canonical_arguments)
        if not decision.approval_required:
            if not decision.allowed:
                raise ValueError(decision.reason)
            raise ValueError("La herramienta no requiere aprobación")

        return canonical_arguments, self.arguments_sha256(canonical_arguments)

    async def _authorize(
        self,
        request: ToolRequest,
        canonical_arguments: dict[str, Any],
    ) -> PolicyDecision:
        decision = self.policy.evaluate(request.tool, canonical_arguments)
        if decision.allowed or not decision.approval_required:
            return decision
        if not request.approval_token:
            return decision
        if self.approval_service is None:
            return self.policy.deny(
                request.tool,
                "El almacén de aprobaciones no está disponible",
                approval_required=True,
            )

        try:
            approved = await self.approval_service.consume(
                request.approval_token,
                request.requested_by,
                request.tool,
                self.arguments_sha256(canonical_arguments),
                request.request_id,
            )
        except Exception:
            logger.exception("No se pudo validar la aprobación de %s", request.request_id)
            approved = False

        if approved is not True:
            return self.policy.deny(
                request.tool,
                "La aprobación no es válida, expiró o ya fue utilizada",
                approval_required=True,
            )
        return self.policy.evaluate(
            request.tool,
            canonical_arguments,
            approval_granted=True,
        )

    async def _execute_adapter(
        self,
        request: ToolRequest,
        canonical_arguments: dict[str, Any],
        decision: PolicyDecision,
        timeout: float,
    ) -> ToolResponse:
        try:
            result: dict[str, Any] = await asyncio.wait_for(
                self.tools[request.tool].execute(canonical_arguments),
                timeout=timeout,
            )
            canonical_result = self.canonical_json(result)
            target = str(
                canonical_arguments.get("target")
                or canonical_arguments.get("host")
                or canonical_arguments.get("cidr")
            )
            evidence = Evidence(
                source=request.tool,
                target=target,
                data=result,
                sha256=hashlib.sha256(canonical_result).hexdigest(),
            )
            return ToolResponse(
                request_id=request.request_id,
                status="completed",
                decision=decision,
                evidence=evidence,
            )
        except TimeoutError:
            return ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error=f"La herramienta superó el límite de {timeout:g} segundos",
            )
        except Exception:
            logger.exception("El adaptador %s falló", request.tool)
            return ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="El adaptador falló de forma controlada",
            )

    async def _record_terminal(
        self,
        request: ToolRequest,
        original_arguments: dict[str, Any],
        normalized_arguments: dict[str, Any] | None,
        response: ToolResponse,
    ) -> ToolResponse:
        try:
            await self.journal.begin(
                ExecutionStart(
                    execution_id=request.request_id,
                    requested_by=request.requested_by,
                    tool_name=request.tool,
                    original_arguments=original_arguments,
                    normalized_arguments=normalized_arguments,
                    policy_decision=response.decision,
                    status=response.status,
                    error=response.error,
                )
            )
        except Exception:
            logger.exception("No se pudo auditar la solicitud %s", request.request_id)
            return response.model_copy(
                update={"error": "No se pudo persistir el registro de auditoría"}
            )
        return response

    @staticmethod
    def canonicalize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
        canonical = ToolBroker.canonical_json(arguments)
        normalized = json.loads(canonical.decode("utf-8"))
        if not isinstance(normalized, dict):
            raise ValueError("Los argumentos normalizados deben ser un objeto JSON")
        return normalized

    @staticmethod
    def arguments_sha256(arguments: dict[str, Any]) -> str:
        return hashlib.sha256(ToolBroker.canonical_json(arguments)).hexdigest()

    @staticmethod
    def canonical_json(value: Any) -> bytes:
        try:
            return json.dumps(
                ToolBroker._normalize_json_value(value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "El contenido no admite normalización JSON canónica"
            ) from exc

    @staticmethod
    def _normalize_json_value(value: Any) -> Any:
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            if not isfinite(value):
                raise ValueError("Los números no finitos no son válidos")
            return 0.0 if value == 0 else value
        if isinstance(value, str):
            return normalize("NFC", value)
        if isinstance(value, list):
            return [ToolBroker._normalize_json_value(item) for item in value]
        if isinstance(value, dict):
            normalized: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("Las claves JSON deben ser texto")
                canonical_key = normalize("NFC", key)
                if canonical_key in normalized:
                    raise ValueError(
                        "Dos claves colisionan después de normalizar Unicode"
                    )
                normalized[canonical_key] = ToolBroker._normalize_json_value(item)
            return normalized
        raise TypeError(f"Tipo no permitido en JSON canónico: {type(value).__name__}")

    @staticmethod
    def _validation_summary(exc: Exception) -> str:
        if isinstance(exc, ValidationError):
            errors = exc.errors(
                include_url=False, include_context=False, include_input=False
            )
            return "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in errors
            )
        return str(exc)
