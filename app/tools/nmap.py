import asyncio
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)


class DiscoverHostsArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    target: str = Field(min_length=1, max_length=45)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        # Permite IP individual o CIDR (máx /24 para IPv4)
        try:
            if "/" in value:
                network = ip_network(value, strict=False)
                if network.version == 4 and network.prefixlen < 24:
                    raise ValueError(
                        "El prefijo CIDR no puede ser más amplio que /24 (máx 256 hosts)"
                    )
                return str(network)
            return str(ip_address(value))
        except ValueError as exc:
            if "más amplio que" in str(exc):
                raise
            raise ValueError(f"Target inválido: {value!r}") from exc


class InspectServicesArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    target: str = Field(min_length=1, max_length=45)
    ports: list[int] | None = Field(default=None, max_length=100)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return str(ip_address(value))

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        if not value:
            raise ValueError("La lista de puertos no puede estar vacía")
        cleaned = sorted(set(value))
        for port in cleaned:
            if not (1 <= port <= 65535):
                raise ValueError(f"Puerto fuera de rango válido (1-65535): {port}")
        return cleaned


def find_nmap_executable() -> str:
    exe = shutil.which("nmap")
    if exe:
        return exe
    # Rutas comunes en Windows
    common_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for path in common_paths:
        if shutil.which(path):
            return path
    raise RuntimeError("Ejecutable nmap no encontrado en el sistema")


class NmapDiscoverHostsTool:
    name = "discover_hosts"
    timeout_seconds = 30.0

    def __init__(self, mode: Literal["mock", "local"] = "mock"):
        self.mode = mode

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return DiscoverHostsArguments.model_validate(arguments).model_dump(mode="json")

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments["target"]

        if self.mode == "mock":
            return {
                "target": target,
                "scan_type": "discover_hosts (mock)",
                "hosts": [
                    {"address": "192.168.10.1", "status": "up", "reason": "syn-ack"},
                    {"address": "192.168.10.25", "status": "up", "reason": "syn-ack"},
                ],
                "total_hosts_up": 2,
                "raw_output": f"<mock-nmap-run target='{target}' hosts_up='2'/>",
            }

        nmap_bin = find_nmap_executable()
        cmd = [nmap_bin, "-sn", "-n", "-oX", "-", target]

        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"Nmap discover_hosts superó el timeout de {self.timeout_seconds}s"
            )

        if completed.returncode != 0:
            err = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Error al ejecutar Nmap: {err}")

        xml_content = completed.stdout.decode("utf-8", errors="replace")
        hosts = self._parse_discover_xml(xml_content)

        return {
            "target": target,
            "scan_type": "discover_hosts",
            "hosts": hosts,
            "total_hosts_up": len(hosts),
            "raw_output": xml_content,
        }

    @staticmethod
    def _parse_discover_xml(xml_string: str) -> list[dict[str, Any]]:
        hosts: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_string)
            for host_el in root.findall("host"):
                status_el = host_el.find("status")
                addr_el = host_el.find("address")
                if status_el is not None and addr_el is not None:
                    state = status_el.get("state")
                    if state == "up":
                        hosts.append({
                            "address": addr_el.get("addr", ""),
                            "status": state,
                            "reason": status_el.get("reason", ""),
                        })
        except ET.ParseError as exc:
            logger.warning("Error parseando XML de Nmap discover: %s", exc)
        return hosts


class NmapInspectServicesTool:
    name = "inspect_services"
    timeout_seconds = 60.0

    def __init__(self, mode: Literal["mock", "local"] = "mock"):
        self.mode = mode

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return InspectServicesArguments.model_validate(arguments).model_dump(mode="json")

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments["target"]
        ports = arguments.get("ports")

        if self.mode == "mock":
            return {
                "target": target,
                "scan_type": "inspect_services (mock)",
                "services": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service_name": "ssh",
                        "product": "OpenSSH",
                        "version": "9.6p1",
                        "cpe": "cpe:/a:openbsd:openssh:9.6p1",
                    },
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service_name": "https",
                        "product": "nginx",
                        "version": "1.24.0",
                        "cpe": "cpe:/a:igor_sysoev:nginx:1.24.0",
                    },
                ],
                "raw_output": f"<mock-nmap-services target='{target}' count='2'/>",
            }

        nmap_bin = find_nmap_executable()
        port_spec = ",".join(str(p) for p in ports) if ports else "21,22,25,80,443,8000,8080,11434"

        # Flags estrictamente fijas: TCP connect unprivileged, probe light, no ping, no DNS
        cmd = [
            nmap_bin,
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "-oX",
            "-",
            "-p",
            port_spec,
            target,
        ]

        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"Nmap inspect_services superó el timeout de {self.timeout_seconds}s"
            )

        if completed.returncode != 0:
            err = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Error al ejecutar Nmap: {err}")

        xml_content = completed.stdout.decode("utf-8", errors="replace")
        services = self._parse_services_xml(xml_content)

        return {
            "target": target,
            "scan_type": "inspect_services",
            "services": services,
            "total_open_ports": len(services),
            "raw_output": xml_content,
        }

    @staticmethod
    def _parse_services_xml(xml_string: str) -> list[dict[str, Any]]:
        services: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_string)
            for port_el in root.findall(".//port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")

                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue

                port_id = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                service_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                cpe_el = service_el.find("cpe") if service_el is not None else None
                cpe = cpe_el.text if cpe_el is not None and cpe_el.text else ""

                services.append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "cpe": cpe,
                })
        except ET.ParseError as exc:
            logger.warning("Error parseando XML de Nmap services: %s", exc)
        return services
