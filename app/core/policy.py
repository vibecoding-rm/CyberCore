from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import yaml

from app.api.models import PolicyDecision


@dataclass(frozen=True)
class ToolPolicy:
    risk: str
    approval: bool
    enabled: bool


class PolicyEngine:
    def __init__(self, policy_path: Path | str):
        with Path(policy_path).open("r", encoding="utf-8") as handle:
            self.config: dict[str, Any] = yaml.safe_load(handle)

        scope = self.config.get("scope", {})
        self.allowed_networks = [ip_network(value) for value in scope.get("allowed_networks", [])]
        self.denied_networks = [ip_network(value) for value in scope.get("denied_networks", [])]
        self.allow_hostnames = bool(scope.get("allow_hostnames", False))

    def evaluate(self, tool_name: str, arguments: dict[str, Any], approval_token: str | None) -> PolicyDecision:
        raw_policy = self.config.get("tools", {}).get(tool_name)
        if raw_policy is None:
            return PolicyDecision(
                allowed=False,
                reason=f"Herramienta no registrada: {tool_name}",
                risk="critical",
            )

        policy = ToolPolicy(
            risk=raw_policy.get("risk", "high"),
            approval=bool(raw_policy.get("approval_required", True)),
            enabled=bool(raw_policy.get("enabled", False)),
        )

        if not policy.enabled:
            return PolicyDecision(
                allowed=False,
                reason=f"Herramienta deshabilitada por política: {tool_name}",
                risk=policy.risk,
                approval_required=policy.approval,
            )

        target = arguments.get("target") or arguments.get("host") or arguments.get("cidr")
        if not target:
            return PolicyDecision(
                allowed=False,
                reason="La solicitud no contiene target, host o cidr",
                risk=policy.risk,
                approval_required=policy.approval,
            )

        scope_result = self._validate_scope(str(target))
        if scope_result is not None:
            return PolicyDecision(
                allowed=False,
                reason=scope_result,
                risk=policy.risk,
                approval_required=policy.approval,
            )

        if policy.approval and not approval_token:
            return PolicyDecision(
                allowed=False,
                reason="La acción está en alcance, pero requiere aprobación humana",
                risk=policy.risk,
                approval_required=True,
            )

        return PolicyDecision(
            allowed=True,
            reason="Solicitud permitida por alcance y política",
            risk=policy.risk,
            approval_required=policy.approval,
        )

    def _validate_scope(self, target: str) -> str | None:
        try:
            candidate = ip_network(target, strict=False) if "/" in target else ip_address(target)
        except ValueError:
            if self.allow_hostnames:
                return None
            return "Los nombres DNS están bloqueados; usa una IP o CIDR autorizado"

        if any(self._overlaps(candidate, network) for network in self.denied_networks):
            return f"Objetivo denegado expresamente por política: {target}"

        if not any(self._contained(candidate, network) for network in self.allowed_networks):
            return f"Objetivo fuera del alcance autorizado: {target}"

        return None

    @staticmethod
    def _contained(candidate: Any, network: Any) -> bool:
        if hasattr(candidate, "subnet_of"):
            return candidate.subnet_of(network)
        return candidate in network

    @staticmethod
    def _overlaps(candidate: Any, network: Any) -> bool:
        if hasattr(candidate, "overlaps"):
            return candidate.overlaps(network)
        return candidate in network
