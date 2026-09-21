from __future__ import annotations

import logging
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path
from typing import Any, Protocol

import yaml

from app.api.models import PolicyDecision


IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network
IPTarget = IPAddress | IPNetwork
VALID_RISKS = {"low", "medium", "high", "critical"}
logger = logging.getLogger(__name__)


class ApprovalValidator(Protocol):
    def consume(
        self,
        token: str,
        requested_by: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> bool: ...


@dataclass(frozen=True)
class ToolPolicy:
    risk: str
    approval: bool
    enabled: bool


@dataclass(frozen=True)
class BudgetPolicy:
    max_targets_per_request: int
    max_duration_seconds: float
    max_parallel_jobs: int
    max_requests_per_hour: int


class PolicyEngine:
    def __init__(
        self,
        policy_path: Path | str,
        approval_validator: ApprovalValidator | None = None,
    ):
        with Path(policy_path).open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)

        if not isinstance(loaded, dict):
            raise ValueError("La política debe ser un objeto YAML")

        self.config: dict[str, Any] = loaded
        self.approval_validator = approval_validator

        scope = self.config.get("scope", {})
        if not isinstance(scope, dict):
            raise ValueError("La sección scope debe ser un objeto")
        self.allowed_networks = self._load_networks(scope.get("allowed_networks", []))
        self.denied_networks = self._load_networks(scope.get("denied_networks", []))
        self.allow_hostnames = self._strict_bool(scope, "allow_hostnames", False)

        budgets = self.config.get("budgets", {})
        if not isinstance(budgets, dict):
            raise ValueError("La sección budgets debe ser un objeto")
        self.budgets = BudgetPolicy(
            max_targets_per_request=self._positive_int(
                budgets, "max_targets_per_request", 1
            ),
            max_duration_seconds=float(
                self._positive_int(budgets, "max_duration_seconds", 30)
            ),
            max_parallel_jobs=self._positive_int(budgets, "max_parallel_jobs", 1),
            max_requests_per_hour=self._positive_int(
                budgets, "max_requests_per_hour", 1
            ),
        )

        raw_tools = self.config.get("tools", {})
        if not isinstance(raw_tools, dict):
            raise ValueError("La sección tools debe ser un objeto")
        self.tool_policies: dict[str, ToolPolicy] = {}
        for name, raw_policy in raw_tools.items():
            if not isinstance(name, str) or not isinstance(raw_policy, dict):
                raise ValueError(
                    "Cada política de herramienta debe ser un objeto con nombre textual"
                )
            risk = raw_policy.get("risk", "high")
            if not isinstance(risk, str) or risk not in VALID_RISKS:
                raise ValueError(f"Nivel de riesgo inválido para {name}: {risk}")
            self.tool_policies[name] = ToolPolicy(
                risk=risk,
                approval=self._strict_bool(raw_policy, "approval_required", True),
                enabled=self._strict_bool(raw_policy, "enabled", False),
            )

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        approval_token: str | None,
        requested_by: str = "operator",
    ) -> PolicyDecision:
        policy = self._tool_policy(tool_name)
        if policy is None:
            return self.deny(tool_name, f"Herramienta no registrada: {tool_name}")

        if not policy.enabled:
            return PolicyDecision(
                allowed=False,
                reason=f"Herramienta deshabilitada por política: {tool_name}",
                risk=policy.risk,
                approval_required=False,
            )

        target = (
            arguments.get("target") or arguments.get("host") or arguments.get("cidr")
        )
        if not target:
            return self.deny(
                tool_name,
                "La solicitud no contiene target, host o cidr",
            )

        scope_result = self._validate_scope(str(target))
        if scope_result is not None:
            return self.deny(tool_name, scope_result)

        if policy.approval:
            if not approval_token:
                return self.deny(
                    tool_name,
                    "La acción está en alcance, pero requiere aprobación humana",
                    approval_required=True,
                )
            if self.approval_validator is None:
                return self.deny(
                    tool_name,
                    "No existe un verificador de aprobaciones configurado",
                    approval_required=True,
                )
            try:
                approved = self.approval_validator.consume(
                    approval_token,
                    requested_by,
                    tool_name,
                    arguments,
                )
            except Exception:
                logger.exception("El verificador de aprobaciones falló")
                approved = False
            if approved is not True:
                return self.deny(
                    tool_name,
                    "La aprobación no es válida para esta solicitud",
                    approval_required=True,
                )

        return PolicyDecision(
            allowed=True,
            reason="Solicitud permitida por alcance y política",
            risk=policy.risk,
            approval_required=policy.approval,
        )

    def deny(
        self,
        tool_name: str,
        reason: str,
        approval_required: bool = False,
    ) -> PolicyDecision:
        policy = self._tool_policy(tool_name)
        risk = policy.risk if policy is not None else "critical"
        return PolicyDecision(
            allowed=False,
            reason=reason,
            risk=risk,
            approval_required=approval_required,
        )

    def _tool_policy(self, tool_name: str) -> ToolPolicy | None:
        return self.tool_policies.get(tool_name)

    def _validate_scope(self, target: str) -> str | None:
        try:
            candidate: IPTarget = (
                ip_network(target, strict=False)
                if "/" in target
                else ip_address(target)
            )
        except ValueError:
            if self.allow_hostnames:
                return "Los nombres DNS aún no tienen validación de resolución segura"
            return "Los nombres DNS están bloqueados; usa una IP o CIDR autorizado"

        target_count = (
            candidate.num_addresses
            if isinstance(candidate, (IPv4Network, IPv6Network))
            else 1
        )
        if target_count > self.budgets.max_targets_per_request:
            return (
                f"El objetivo contiene {target_count} direcciones; el límite es "
                f"{self.budgets.max_targets_per_request}"
            )

        matching_denied = [
            network
            for network in self.denied_networks
            if network.version == candidate.version
        ]
        if any(self._overlaps(candidate, network) for network in matching_denied):
            return f"Objetivo denegado expresamente por política: {target}"

        matching_allowed = [
            network
            for network in self.allowed_networks
            if network.version == candidate.version
        ]
        if not any(self._contained(candidate, network) for network in matching_allowed):
            return f"Objetivo fuera del alcance autorizado: {target}"

        return None

    @staticmethod
    def _load_networks(values: Any) -> list[IPNetwork]:
        if not isinstance(values, list):
            raise ValueError("Las redes de alcance deben declararse como una lista")
        return [ip_network(str(value), strict=True) for value in values]

    @staticmethod
    def _positive_int(config: dict[str, Any], key: str, default: int) -> int:
        value = config.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"El presupuesto {key} debe ser un entero positivo")
        return value

    @staticmethod
    def _strict_bool(config: dict[str, Any], key: str, default: bool) -> bool:
        value = config.get(key, default)
        if not isinstance(value, bool):
            raise ValueError(f"El valor {key} debe ser booleano")
        return value

    @staticmethod
    def _contained(candidate: IPTarget, network: IPNetwork) -> bool:
        if isinstance(candidate, (IPv4Network, IPv6Network)):
            return candidate.subnet_of(network)
        return candidate in network

    @staticmethod
    def _overlaps(candidate: IPTarget, network: IPNetwork) -> bool:
        if isinstance(candidate, (IPv4Network, IPv6Network)):
            return candidate.overlaps(network)
        return candidate in network
