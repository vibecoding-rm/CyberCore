import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

TemplateMode = Literal["passive", "active"]

# Protocols that execute code, drive a browser, read local files or run
# multi-step scripted flows are outside what a pinned HTTP check may do.
_FORBIDDEN_TEMPLATE_KEYS = {"code", "headless", "javascript", "file", "flow", "workflows"}
_HTTP_KEYS = {"http", "requests"}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class NucleiTemplateError(ValueError):
    """Raised when a template is not allowlisted or fails its integrity checks."""


class AllowedTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    path: str = Field(min_length=6, max_length=512)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: TemplateMode
    description: str = Field(min_length=1, max_length=500)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(f"Identificador de plantilla inválido: {value!r}")
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        # Judge the path the same way on every OS: "/x" has no drive on
        # Windows, so pathlib alone would not call it absolute there.
        candidate = PurePosixPath(value)
        if (
            value.startswith("/")
            or "\\" in value
            or ":" in value
            or ".." in candidate.parts
            or candidate.suffix != ".yaml"
        ):
            raise ValueError(f"Ruta de plantilla no permitida: {value!r}")
        return candidate.as_posix()


class VerifiedTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    mode: TemplateMode
    sha256: str
    path: str
    content: bytes


class NucleiTemplateCatalog:
    """Human-curated allowlist of Nuclei templates pinned by SHA-256."""

    def __init__(self, templates_dir: Path | str, templates: list[AllowedTemplate]):
        self.templates_dir = Path(templates_dir).expanduser()
        ids = [template.id for template in templates]
        if len(ids) != len(set(ids)):
            raise ValueError("El allowlist de Nuclei contiene identificadores duplicados")
        self.templates = {template.id: template for template in templates}

    @classmethod
    def from_yaml(cls, allowlist_file: Path | str, templates_dir: Path | str) -> "NucleiTemplateCatalog":
        path = Path(allowlist_file)
        if not path.is_file():
            return cls(templates_dir, [])
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        if not isinstance(loaded, dict):
            raise ValueError("El allowlist de Nuclei debe ser un objeto YAML")
        raw = loaded.get("templates") or []
        if not isinstance(raw, list):
            raise ValueError("La sección templates del allowlist debe ser una lista")
        return cls(templates_dir, [AllowedTemplate.model_validate(item) for item in raw])

    def get(self, template_id: str) -> AllowedTemplate:
        template = self.templates.get(template_id)
        if template is None:
            raise NucleiTemplateError(f"La plantilla {template_id!r} no está en el allowlist")
        return template

    def verify(self, template_id: str) -> VerifiedTemplate:
        """Load the template bytes and prove they are the reviewed, pinned content."""
        allowed = self.get(template_id)
        root = self.templates_dir.resolve()
        file_path = (root / allowed.path).resolve()
        if not file_path.is_relative_to(root):
            raise NucleiTemplateError(f"La plantilla {template_id} sale del directorio permitido")
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            raise NucleiTemplateError(f"No se pudo leer la plantilla {template_id}") from exc

        digest = hashlib.sha256(content).hexdigest()
        if digest != allowed.sha256:
            raise NucleiTemplateError(
                f"El hash de {template_id} no coincide con el fijado; revisa la plantilla "
                "y actualiza el allowlist si el cambio es legítimo"
            )
        inspect_template_content(content, template_id)
        return VerifiedTemplate(
            id=allowed.id,
            mode=allowed.mode,
            sha256=digest,
            path=allowed.path,
            content=content,
        )


def inspect_template_content(content: bytes, expected_id: str) -> dict[str, Any]:
    """Reject templates that are not plain, target-bound HTTP checks."""
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise NucleiTemplateError(f"La plantilla {expected_id} no es YAML válido") from exc
    if not isinstance(parsed, dict):
        raise NucleiTemplateError(f"La plantilla {expected_id} no es un objeto YAML")
    if parsed.get("id") != expected_id:
        raise NucleiTemplateError(
            f"La plantilla declara id {parsed.get('id')!r}, se esperaba {expected_id!r}"
        )
    forbidden = _FORBIDDEN_TEMPLATE_KEYS & parsed.keys()
    if forbidden:
        raise NucleiTemplateError(
            f"La plantilla {expected_id} usa protocolos no permitidos: {sorted(forbidden)}"
        )
    if not _HTTP_KEYS & parsed.keys():
        raise NucleiTemplateError(f"La plantilla {expected_id} no es una plantilla HTTP")
    if parsed.get("self-contained") is True:
        raise NucleiTemplateError(
            f"La plantilla {expected_id} es self-contained e ignora el objetivo autorizado"
        )
    for block in (parsed.get("http") or []) + (parsed.get("requests") or []):
        if isinstance(block, dict) and block.get("self-contained") is True:
            raise NucleiTemplateError(
                f"La plantilla {expected_id} contiene peticiones self-contained"
            )
    return parsed
