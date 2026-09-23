from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IntelSource = Literal["nvd", "osv"]


class AffectedRange(BaseModel):
    """One affected product/package declaration taken verbatim from a source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    match_kind: Literal["cpe", "package"]
    vendor: str | None = None
    product: str = Field(min_length=1)
    ecosystem: str | None = None
    range_type: Literal["cpe", "semver", "ecosystem", "exact"]
    exact_version: str | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    requires_platform: bool = False
    criteria: str = Field(min_length=1)


class NormalizedVulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    source: IntelSource
    source_url: str
    description: str | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    published_at: datetime | None = None
    source_modified_at: datetime | None = None
    ranges: list[AffectedRange] = Field(default_factory=list)


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
