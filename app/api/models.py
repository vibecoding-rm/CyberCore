import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.intelligence.matching import VersionMatch


class ToolRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID = Field(default_factory=uuid4)
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict, max_length=32)
    approval_token: str | None = Field(default=None, min_length=1, max_length=500)


class ToolRequest(ToolRequestInput):
    requested_by: str = Field(min_length=1, max_length=100)


class ApprovalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requested_by: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-zA-Z0-9._-]+$",
    )
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict, max_length=32)
    expires_in_seconds: int = Field(default=900, ge=60, le=86400)


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: UUID
    approval_token: str
    requested_by: str
    approved_by: str
    tool: str
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: datetime


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    risk: Literal["low", "medium", "high", "critical"]
    approval_required: bool = False


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid4().hex[:12].upper()}")
    source: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target: str
    data: dict[str, Any]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ToolResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    status: Literal["completed", "denied", "approval_required", "failed"]
    decision: PolicyDecision
    evidence: Evidence | None = None
    error: str | None = None


class InventoryAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID = Field(default_factory=uuid4)
    target: str = Field(min_length=1, max_length=45)
    vulnerability_id: str | None = Field(
        default=None,
        pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$",
    )


class EvidenceGap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: Literal[
        "real_inventory",
        "vulnerability_identifier",
        "service_product_version",
        "authoritative_advisory",
        "affected_version_range",
        "independent_validation",
    ]
    description: str
    recommended_action: str


class EvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Literal["need_more_evidence", "sufficient_evidence"] = "need_more_evidence"
    finding_status: Literal["candidate", "probable", "confirmed"] = "candidate"
    can_confirm: bool = False
    target: str
    vulnerability_id: str | None
    source_evidence_id: str
    observations: list[str]
    missing_evidence: list[EvidenceGap]
    version_matches: list[VersionMatch] = Field(default_factory=list)
    validation_evidence_ids: list[str] = Field(default_factory=list)
    conclusion: str


EVIDENCE_ID_PATTERN = r"^EVD-[0-9A-F]{12}$"


class EvidenceAnalysisRequest(BaseModel):
    """Assess sealed evidence already collected by the broker, referenced by id."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")
    inventory_evidence_id: str = Field(pattern=EVIDENCE_ID_PATTERN)
    validation_evidence_ids: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("validation_evidence_ids")
    @classmethod
    def validate_ids(cls, value: list[str]) -> list[str]:
        for evidence_id in value:
            if not re.match(EVIDENCE_ID_PATTERN, evidence_id):
                raise ValueError(f"Identificador de evidencia inválido: {evidence_id!r}")
        if len(set(value)) != len(value):
            raise ValueError("Identificadores de evidencia duplicados")
        return value


class FindingExportRequest(EvidenceAnalysisRequest):
    dry_run: bool = False


class FindingExportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exported: bool
    dry_run: bool
    assessment: EvidenceAssessment
    finding: dict[str, Any]
    defectdojo: dict[str, Any] | None = None


class InventoryAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inventory: ToolResponse
    assessment: EvidenceAssessment | None = None


class VersionMatchRequest(BaseModel):
    """Either an observed CPE (as reported by Nmap) or an OSV package version."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")
    cpe: str | None = Field(default=None, min_length=7, max_length=256)
    ecosystem: str | None = Field(default=None, min_length=1, max_length=64)
    package: str | None = Field(default=None, min_length=1, max_length=256)
    version: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_one_subject(self) -> "VersionMatchRequest":
        package_fields = (self.ecosystem, self.package, self.version)
        if self.cpe is not None and any(f is not None for f in package_fields):
            raise ValueError("Indica cpe o ecosystem/package/version, no ambos")
        if self.cpe is None and not all(f is not None for f in package_fields):
            raise ValueError("Se requiere cpe o ecosystem, package y version")
        return self
