import asyncio
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from ipaddress import IPv4Address, ip_address, ip_network, summarize_address_range
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

MAX_RESULTS = 1000
_BUSY_STATUSES = {"Requested", "Queued", "Running"}


class GreenboneError(RuntimeError):
    """Raised when gvmd is unavailable, refuses an operation or breaks scope."""


class GreenboneSettings(BaseModel):
    """gvmd connection chosen by the administrator, never by the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user: str
    password: SecretStr
    socket_path: str | None = None
    host: str | None = None
    port: int = Field(default=9390, ge=1, le=65535)
    cafile: str | None = None
    timeout_seconds: float = Field(default=60.0, gt=0, le=300)


class GmpSession(Protocol):
    def get_task(self, task_id: str) -> Any: ...
    def get_target(self, target_id: str) -> Any: ...
    def start_task(self, task_id: str) -> Any: ...
    def get_report(self, report_id: str, **kwargs: Any) -> Any: ...


SessionFactory = Callable[[GreenboneSettings], AbstractContextManager[GmpSession]]


@contextmanager
def open_gmp_session(settings: GreenboneSettings) -> Iterator[GmpSession]:
    """Authenticated GMP session; every non-ok gvmd response raises GvmError."""
    from gvm.connections import TLSConnection, UnixSocketConnection
    from gvm.errors import GvmError
    from gvm.protocols.gmp import GMP
    from gvm.transforms import EtreeCheckCommandTransform

    if settings.socket_path:
        connection = UnixSocketConnection(
            path=settings.socket_path, timeout=settings.timeout_seconds
        )
    elif settings.host:
        connection = TLSConnection(
            hostname=settings.host,
            port=settings.port,
            cafile=settings.cafile,
            timeout=settings.timeout_seconds,
        )
    else:
        raise GreenboneError("Greenbone necesita GREENBONE_SOCKET_PATH o GREENBONE_HOST")
    try:
        with GMP(connection=connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(settings.user, settings.password.get_secret_value())
            yield gmp
    except GvmError as exc:
        raise GreenboneError("Greenbone rechazó la operación o la autenticación") from exc
    except OSError as exc:
        raise GreenboneError("No se pudo conectar con gvmd") from exc


def _hosts_in_spec(spec: str) -> list[Any]:
    """Expand a gvmd host list into networks; hostnames cannot be scope-checked."""
    networks: list[Any] = []
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            if "/" in item:
                networks.append(ip_network(item, strict=False))
            elif "-" in item:
                start_text, end_text = (part.strip() for part in item.split("-", 1))
                start = ip_address(start_text)
                if "." not in end_text and ":" not in end_text:
                    # Short IPv4 form: 192.168.10.1-50
                    prefix = start_text.rsplit(".", 1)[0]
                    end_text = f"{prefix}.{end_text}"
                end = ip_address(end_text)
                if not isinstance(start, IPv4Address) or not isinstance(end, IPv4Address):
                    raise ValueError(item)
                networks.extend(summarize_address_range(start, end))
            else:
                address = ip_address(item)
                networks.append(ip_network(address))
        except ValueError as exc:
            raise GreenboneError(
                f"El objetivo de Greenbone contiene {item!r}, que no puede verificarse "
                "contra el alcance (sólo IP, CIDR o rangos IPv4)"
            ) from exc
    if not networks:
        raise GreenboneError("El objetivo de Greenbone no declara hosts")
    return networks


def ensure_hosts_within(spec: str, authorized: str) -> list[str]:
    allowed = ip_network(authorized, strict=False)
    networks = _hosts_in_spec(spec)
    outside = [
        str(net) for net in networks
        if net.version != allowed.version or not net.subnet_of(allowed)
    ]
    if outside:
        raise GreenboneError(
            f"La tarea de Greenbone incluye hosts fuera del objetivo autorizado: {outside}"
        )
    return [str(net) for net in networks]


def _text(element: Any, path: str) -> str | None:
    found = element.find(path) if element is not None else None
    if found is None or found.text is None:
        return None
    return found.text.strip()


def _normalize_target(value: str) -> str:
    return str(ip_network(value, strict=False)) if "/" in value else str(ip_address(value))


class GreenboneTaskArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: str
    target: str = Field(min_length=1, max_length=49)

    @field_validator("task_id")
    @classmethod
    def validate_task_id(cls, value: str) -> str:
        return str(UUID(value))

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _normalize_target(value)


class GreenboneResultsArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    report_id: str
    target: str = Field(min_length=1, max_length=49)

    @field_validator("report_id")
    @classmethod
    def validate_report_id(cls, value: str) -> str:
        return str(UUID(value))

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _normalize_target(value)


class _GreenboneBase:
    timeout_seconds = 90.0

    def __init__(
        self,
        settings: GreenboneSettings | None,
        mode: Literal["mock", "local"] = "mock",
        session_factory: SessionFactory = open_gmp_session,
    ):
        self.settings = settings
        self.mode = mode
        self.session_factory = session_factory

    def _require_settings(self) -> GreenboneSettings:
        if self.settings is None:
            raise GreenboneError("La conexión con Greenbone no está configurada")
        return self.settings


class GreenboneStartTaskTool(_GreenboneBase):
    """Start an existing gvmd task only if every host it scans is inside the approved target."""

    name = "start_greenbone_task"

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return GreenboneTaskArguments.model_validate(arguments).model_dump(mode="json")

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.mode == "mock":
            return {
                "target": arguments["target"],
                "source": "simulated",
                "scan_type": "start_greenbone_task (mock)",
                "task_id": arguments["task_id"],
                "task_name": "Tarea simulada",
                "scanned_hosts": [arguments["target"]],
                "report_id": "00000000-0000-4000-8000-000000000000",
                "notice": "No se inició ninguna tarea real en Greenbone.",
            }
        settings = self._require_settings()
        return await asyncio.to_thread(self._start, settings, arguments)

    def _start(self, settings: GreenboneSettings, arguments: dict[str, Any]) -> dict[str, Any]:
        with self.session_factory(settings) as gmp:
            task = gmp.get_task(arguments["task_id"]).find("task")
            if task is None:
                raise GreenboneError("La tarea indicada no existe en Greenbone")
            status = _text(task, "status")
            if status in _BUSY_STATUSES:
                raise GreenboneError(f"La tarea ya está en curso (estado {status})")
            target_el = task.find("target")
            gvm_target_id = target_el.get("id") if target_el is not None else None
            if not gvm_target_id:
                raise GreenboneError("La tarea no tiene un objetivo asociado")
            target = gmp.get_target(gvm_target_id).find("target")
            hosts_spec = _text(target, "hosts") or ""
            # The scope check binds gvmd's real configuration to the target the
            # policy validated and the approver signed, before anything starts.
            scanned = ensure_hosts_within(hosts_spec, arguments["target"])
            report_id = _text(gmp.start_task(arguments["task_id"]), "report_id")
            if not report_id:
                raise GreenboneError("Greenbone no devolvió un identificador de informe")
        return {
            "target": arguments["target"],
            "source": "greenbone",
            "scan_type": "start_greenbone_task",
            "task_id": arguments["task_id"],
            "task_name": _text(task, "name"),
            "gvm_target_id": gvm_target_id,
            "scanned_hosts": scanned,
            "report_id": report_id,
        }


class GreenboneResultsTool(_GreenboneBase):
    """Read a report's results, refusing reports that cover hosts outside the target."""

    name = "get_greenbone_results"

    def validate_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return GreenboneResultsArguments.model_validate(arguments).model_dump(mode="json")

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.mode == "mock":
            return {
                "target": arguments["target"],
                "source": "simulated",
                "scan_type": "get_greenbone_results (mock)",
                "report_id": arguments["report_id"],
                "scan_run_status": "Done",
                "results": [],
                "total_results": 0,
                "results_truncated": False,
                "notice": "No se consultó ningún Greenbone real.",
            }
        settings = self._require_settings()
        return await asyncio.to_thread(self._results, settings, arguments)

    def _results(self, settings: GreenboneSettings, arguments: dict[str, Any]) -> dict[str, Any]:
        with self.session_factory(settings) as gmp:
            response = gmp.get_report(
                arguments["report_id"],
                filter_string="apply_overrides=1 min_qod=70 rows=-1",
                ignore_pagination=True,
                details=True,
            )
        report = response.find("report")
        if report is None:
            raise GreenboneError("El informe indicado no existe en Greenbone")
        results = [self._result(el) for el in report.iter("result")]
        hosts = sorted({r["host"] for r in results if r["host"]})
        if hosts:
            try:
                ensure_hosts_within(",".join(hosts), arguments["target"])
            except GreenboneError as exc:
                # Do not echo the foreign hosts: they are what must stay hidden.
                raise GreenboneError(
                    "El informe contiene resultados de hosts fuera del objetivo autorizado"
                ) from exc
        return {
            "target": arguments["target"],
            "source": "greenbone",
            "scan_type": "get_greenbone_results",
            "report_id": arguments["report_id"],
            "scan_run_status": next(
                (el.text for el in report.iter("scan_run_status") if el.text), None
            ),
            "results": results[:MAX_RESULTS],
            "total_results": len(results),
            "results_truncated": len(results) > MAX_RESULTS,
        }

    @staticmethod
    def _result(element: Any) -> dict[str, Any]:
        host_el = element.find("host")
        nvt = element.find("nvt")
        qod = _text(element, "qod/value")
        severity = _text(element, "severity")
        return {
            "host": host_el.text.strip() if host_el is not None and host_el.text else None,
            "port": _text(element, "port"),
            "nvt_oid": nvt.get("oid") if nvt is not None else None,
            "name": _text(element, "name") or _text(nvt, "name"),
            "severity": float(severity) if severity else None,
            "threat": _text(element, "threat"),
            "qod": int(qod) if qod and qod.isdigit() else None,
            "cve_ids": sorted(
                {
                    ref.get("id").upper()
                    for ref in (nvt.iter("ref") if nvt is not None else [])
                    if ref.get("type") == "cve" and ref.get("id")
                }
            ),
        }
