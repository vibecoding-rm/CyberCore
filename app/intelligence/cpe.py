from pydantic import BaseModel, ConfigDict

_WILDCARDS = {"*", "-", ""}


class CpeName(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    part: str
    vendor: str
    product: str
    version: str | None = None

    @property
    def key(self) -> str:
        return f"{self.vendor}:{self.product}"


def _unescape(value: str) -> str:
    return value.replace("\\", "").lower()


def parse_cpe(value: str) -> CpeName | None:
    """Parse CPE 2.3 formatted strings and CPE 2.2 URIs (as emitted by Nmap).

    The update field is folded into the version (``8.5`` + ``p1`` -> ``8.5p1``)
    so NVD and Nmap spellings of the same release compare equal.
    """
    raw = value.strip()
    if raw.startswith("cpe:2.3:"):
        fields = raw[len("cpe:2.3:"):].split(":")
    elif raw.startswith("cpe:/"):
        fields = raw[len("cpe:/"):].split(":")
    else:
        return None
    if len(fields) < 3 or fields[0] not in {"a", "o", "h"}:
        return None

    vendor, product = _unescape(fields[1]), _unescape(fields[2])
    if vendor in _WILDCARDS or product in _WILDCARDS:
        return None

    version = _unescape(fields[3]) if len(fields) > 3 else ""
    update = _unescape(fields[4]) if len(fields) > 4 else ""
    if version in _WILDCARDS:
        version = ""
    elif update not in _WILDCARDS:
        version = f"{version}{update}"
    return CpeName(part=fields[0], vendor=vendor, product=product, version=version or None)
