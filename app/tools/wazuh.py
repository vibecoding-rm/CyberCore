import re
from ipaddress import ip_address
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

MAX_PACKAGES = 5000
_PAGE_SIZE = 500
_AGENT_FIELDS = "id,name,ip,status,lastKeepAlive,version"
_AGENT_ID_RE = re.compile(r"^\d{3,6}$")
_PACKAGE_FIELDS = ("name", "version", "vendor", "architecture", "format", "source")


class WazuhError(RuntimeError):
    """Raised when the Wazuh server API is unavailable or answers invalidly."""


class WazuhInventoryArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    target: str = Field(min_length=1, max_length=45)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return str(ip_address(value))


class WazuhSettings(BaseModel):
    """Manager connection chosen by the administrator, never by the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    base_url: str
    user: str
    password: SecretStr
    verify_tls: bool = True
    ca_bundle: str | None = None
    timeout_seconds: float = Field(default=20.0, gt=0, le=120)

    @property
    def verify(self) -> bool | str:
        if self.ca_bundle:
            return self.ca_bundle
        return self.verify_tls


def _items(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("error") not in (0, None):
        raise WazuhError("Wazuh devolvió un error en la respuesta")
    data = payload.get("data")
    items = data.get("affected_items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise WazuhError("Wazuh devolvió una respuesta sin affected_items")
    return [item for item in items if isinstance(item, dict)]


class WazuhInventoryTool:
    """Read-only inventory of one agent (OS, packages, listening ports) via the Wazuh API."""

    name = "get_wazuh_inventory"
    timeout_seconds = 60.0

    def __init__(
        self,
        settings: WazuhSettings | None,
        mode: Literal["mock", "local"] = "mock",
        http_client: httpx.AsyncClient | None = None,
    ):
        self.settings = settings
        self.mode = mode
        self._http_client = http_client

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return WazuhInventoryArguments.model_validate(arguments).model_dump(mode="json")

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments["target"]
        if self.mode == "mock":
            return self._mock_result(target)
        if self.settings is None:
            raise WazuhError("La conexión con Wazuh no está configurada")

        client = self._http_client or httpx.AsyncClient(
            base_url=self.settings.base_url.rstrip("/"),
            timeout=self.settings.timeout_seconds,
            verify=self.settings.verify,
        )
        try:
            token = await self._authenticate(client, self.settings)
            headers = {"Authorization": f"Bearer {token}"}
            listed = _items(
                await self._get(client, "/agents", headers, {"ip": target, "select": _AGENT_FIELDS})
            )
            # Re-filter locally: a server ignoring the ip filter must not make
            # us report (or pick) agents that belong to other hosts.
            agents = [a for a in listed if a.get("ip") == target]
            if len(agents) != 1:
                return self._no_single_agent(target, agents)
            agent = agents[0]
            agent_id = str(agent.get("id"))
            if not _AGENT_ID_RE.match(agent_id):
                raise WazuhError("Wazuh devolvió un identificador de agente inválido")
            os_items = _items(await self._get(client, f"/syscollector/{agent_id}/os", headers, {}))
            packages, truncated = await self._packages(client, agent_id, headers)
            ports = _items(
                await self._get(
                    client,
                    f"/syscollector/{agent_id}/ports",
                    headers,
                    {"state": "listening", "limit": _PAGE_SIZE},
                )
            )
        finally:
            if self._http_client is None:
                await client.aclose()

        return {
            "target": target,
            "source": "wazuh",
            "scan_type": "get_wazuh_inventory",
            "agent": {
                "id": agent_id,
                "name": agent.get("name"),
                "ip": agent.get("ip"),
                "status": agent.get("status"),
                "last_keepalive": agent.get("lastKeepAlive"),
                "version": agent.get("version"),
            },
            "operating_system": self._os(os_items),
            "packages": packages,
            "total_packages": len(packages),
            "packages_truncated": truncated,
            "listening_ports": self._ports(ports),
        }

    @staticmethod
    async def _authenticate(client: httpx.AsyncClient, settings: WazuhSettings) -> str:
        try:
            response = await client.post(
                "/security/user/authenticate",
                params={"raw": "true"},
                auth=(settings.user, settings.password.get_secret_value()),
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise WazuhError(
                f"Wazuh rechazó la autenticación (HTTP {exc.response.status_code})"
            ) from exc
        except httpx.RequestError as exc:
            raise WazuhError("No se pudo conectar con la API de Wazuh") from exc
        token = response.text.strip()
        if not token or " " in token:
            raise WazuhError("Wazuh devolvió un token inválido")
        return token

    async def _get(
        self,
        client: httpx.AsyncClient,
        path: str,
        headers: dict[str, str],
        params: dict[str, Any],
    ) -> Any:
        try:
            response = await client.get(path, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            raise WazuhError(f"Wazuh respondió con HTTP {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise WazuhError("No se pudo conectar con la API de Wazuh") from exc
        except ValueError as exc:
            raise WazuhError("Wazuh devolvió JSON inválido") from exc

    async def _packages(
        self,
        client: httpx.AsyncClient,
        agent_id: str,
        headers: dict[str, str],
    ) -> tuple[list[dict[str, Any]], bool]:
        packages: list[dict[str, Any]] = []
        offset = 0
        while True:
            payload = await self._get(
                client,
                f"/syscollector/{agent_id}/packages",
                headers,
                {"offset": offset, "limit": _PAGE_SIZE, "select": ",".join(_PACKAGE_FIELDS)},
            )
            page = _items(payload)
            packages.extend(
                {field: item.get(field) for field in _PACKAGE_FIELDS} for item in page
            )
            total = payload["data"].get("total_affected_items", len(packages))
            offset += len(page)
            if not page or offset >= total:
                return packages, False
            if len(packages) >= MAX_PACKAGES:
                return packages[:MAX_PACKAGES], True

    @staticmethod
    def _os(items: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not items:
            return None
        item = items[0]
        os_info = item.get("os") if isinstance(item.get("os"), dict) else {}
        return {
            "name": os_info.get("name"),
            "version": os_info.get("version"),
            "platform": os_info.get("platform"),
            "kernel": (item.get("os_release") or item.get("release")),
            "hostname": item.get("hostname"),
            "architecture": item.get("architecture"),
        }

    @staticmethod
    def _ports(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ports = []
        for item in items:
            local = item.get("local") if isinstance(item.get("local"), dict) else {}
            ports.append(
                {
                    "port": local.get("port"),
                    "local_ip": local.get("ip"),
                    "protocol": item.get("protocol"),
                    "process": item.get("process"),
                    "pid": item.get("pid"),
                }
            )
        return ports

    @staticmethod
    def _no_single_agent(target: str, agents: list[dict[str, Any]]) -> dict[str, Any]:
        reason = (
            "No hay ningún agente Wazuh registrado con esa IP."
            if not agents
            else "Varios agentes Wazuh comparten esa IP; no se elige uno arbitrariamente."
        )
        return {
            "target": target,
            "source": "wazuh",
            "scan_type": "get_wazuh_inventory",
            "agent": None,
            "candidate_agents": [
                {"id": a.get("id"), "name": a.get("name"), "status": a.get("status")}
                for a in agents
            ],
            "operating_system": None,
            "packages": [],
            "total_packages": 0,
            "packages_truncated": False,
            "listening_ports": [],
            "notice": reason,
        }

    @staticmethod
    def _mock_result(target: str) -> dict[str, Any]:
        packages = [
            {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5", "vendor": "Ubuntu Developers",
             "architecture": "amd64", "format": "deb", "source": "openssh"},
            {"name": "nginx", "version": "1.24.0-2ubuntu7.1", "vendor": "Ubuntu Developers",
             "architecture": "amd64", "format": "deb", "source": "nginx"},
            {"name": "openssl", "version": "3.0.13-0ubuntu3.4", "vendor": "Ubuntu Developers",
             "architecture": "amd64", "format": "deb", "source": "openssl"},
        ]
        return {
            "target": target,
            "source": "simulated",
            "scan_type": "get_wazuh_inventory (mock)",
            "agent": {"id": "001", "name": "lab-web-01", "ip": target, "status": "active",
                      "last_keepalive": None, "version": "mock"},
            "operating_system": {"name": "Ubuntu", "version": "24.04 LTS", "platform": "ubuntu",
                                 "kernel": None, "hostname": "lab-web-01", "architecture": "x86_64"},
            "packages": packages,
            "total_packages": len(packages),
            "packages_truncated": False,
            "listening_ports": [
                {"port": 22, "local_ip": "0.0.0.0", "protocol": "tcp", "process": "sshd", "pid": None},
                {"port": 443, "local_ip": "0.0.0.0", "protocol": "tcp", "process": "nginx", "pid": None},
            ],
            "notice": "No se consultó ningún servidor Wazuh real.",
        }
