import asyncio
import hashlib
import json
import logging
from collections import deque
from math import isfinite
from time import monotonic
from typing import Any
from unicodedata import normalize

from pydantic import ValidationError

from app.api.models import Evidence, ToolRequest, ToolResponse
from app.core.policy import PolicyEngine
from app.tools.base import ToolAdapter


logger = logging.getLogger(__name__)


class ToolBroker:
    def __init__(
        self,
        policy: PolicyEngine,
        tools: list[ToolAdapter],
        tool_mode: str = "mock",
    ):
        if tool_mode != "mock":
            raise ValueError(f"Modo de herramientas inválido: {tool_mode}")

        names = [tool.name for tool in tools]
        if len(names) != len(set(names)):
            raise ValueError("No se permiten adaptadores con nombres duplicados")
        if any(tool.mode != "mock" for tool in tools):
            raise ValueError("TOOL_MODE=mock sólo permite adaptadores simulados")

        self.policy = policy
        self.tools = {tool.name: tool for tool in tools}
        self.tool_mode = tool_mode
        self._parallel_jobs = asyncio.Semaphore(policy.budgets.max_parallel_jobs)
        self._request_times: deque[float] = deque()

    async def execute(self, request: ToolRequest) -> ToolResponse:
        if not self._reserve_request():
            decision = self.policy.deny(
                request.tool,
                "Se alcanzó el límite de solicitudes por hora",
            )
            return ToolResponse(
                request_id=request.request_id, status="denied", decision=decision
            )

        tool = self.tools.get(request.tool)
        if tool is None:
            decision = self.policy.evaluate(
                request.tool,
                request.arguments,
                request.approval_token,
                request.requested_by,
            )
            if not decision.allowed:
                status = "approval_required" if decision.approval_required else "denied"
                return ToolResponse(
                    request_id=request.request_id, status=status, decision=decision
                )
            return ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="El adaptador permitido no está cargado",
            )

        try:
            normalized_arguments = tool.validate_arguments(request.arguments)
            canonical_arguments = self.canonicalize_arguments(normalized_arguments)
        except (ValidationError, ValueError, TypeError) as exc:
            decision = self.policy.deny(
                request.tool,
                f"Argumentos inválidos para la herramienta: {self._validation_summary(exc)}",
            )
            return ToolResponse(
                request_id=request.request_id, status="denied", decision=decision
            )

        decision = self.policy.evaluate(
            request.tool,
            canonical_arguments,
            request.approval_token,
            request.requested_by,
        )
        if not decision.allowed:
            status = "approval_required" if decision.approval_required else "denied"
            return ToolResponse(
                request_id=request.request_id, status=status, decision=decision
            )

        timeout = min(
            float(tool.timeout_seconds), self.policy.budgets.max_duration_seconds
        )
        if not isfinite(timeout) or timeout <= 0:
            decision = self.policy.deny(
                request.tool, "El timeout del adaptador no es válido"
            )
            return ToolResponse(
                request_id=request.request_id, status="denied", decision=decision
            )

        try:
            async with self._parallel_jobs:
                result: dict[str, Any] = await asyncio.wait_for(
                    tool.execute(canonical_arguments),
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

    @staticmethod
    def canonicalize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
        canonical = ToolBroker.canonical_json(arguments)
        normalized = json.loads(canonical.decode("utf-8"))
        if not isinstance(normalized, dict):
            raise ValueError("Los argumentos normalizados deben ser un objeto JSON")
        return normalized

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

    def _reserve_request(self) -> bool:
        now = monotonic()
        one_hour_ago = now - 3600
        while self._request_times and self._request_times[0] <= one_hour_ago:
            self._request_times.popleft()
        if len(self._request_times) >= self.policy.budgets.max_requests_per_hour:
            return False
        self._request_times.append(now)
        return True

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
