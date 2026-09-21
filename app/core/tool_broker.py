import hashlib
import json
from typing import Any

from app.api.models import Evidence, ToolRequest, ToolResponse
from app.core.policy import PolicyEngine
from app.tools.base import ToolAdapter


class ToolBroker:
    def __init__(self, policy: PolicyEngine, tools: list[ToolAdapter]):
        self.policy = policy
        self.tools = {tool.name: tool for tool in tools}

    async def execute(self, request: ToolRequest) -> ToolResponse:
        decision = self.policy.evaluate(request.tool, request.arguments, request.approval_token)
        if not decision.allowed:
            status = "approval_required" if decision.approval_required else "denied"
            return ToolResponse(request_id=request.request_id, status=status, decision=decision)

        tool = self.tools.get(request.tool)
        if tool is None:
            return ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error="El adaptador permitido no está cargado",
            )

        try:
            result: dict[str, Any] = await tool.execute(request.arguments)
            canonical = json.dumps(result, sort_keys=True, ensure_ascii=False).encode("utf-8")
            target = str(
                request.arguments.get("target")
                or request.arguments.get("host")
                or request.arguments.get("cidr")
            )
            evidence = Evidence(
                source=request.tool,
                target=target,
                data=result,
                sha256=hashlib.sha256(canonical).hexdigest(),
            )
            return ToolResponse(
                request_id=request.request_id,
                status="completed",
                decision=decision,
                evidence=evidence,
            )
        except Exception as exc:
            return ToolResponse(
                request_id=request.request_id,
                status="failed",
                decision=decision,
                error=f"{type(exc).__name__}: {exc}",
            )
