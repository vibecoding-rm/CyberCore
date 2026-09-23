"""Deterministic rules used both as benchmark ground truth and in the prompt.

The benchmark must measure whether a model applies CyberCore's policy, so the
labels come from these functions (and from PolicyEngine, evaluate_range and
decide_status) instead of hand-written answers, and the prompt states the
rules without examples taken from the cases.
"""

from typing import Literal

Priority = Literal["low", "medium", "high", "critical"]
Exposure = Literal["public", "internal"]


def contextual_priority(
    *,
    cvss: float,
    epss: float,
    kev: bool,
    exposure: Exposure,
    asset_criticality: int,
) -> Priority:
    """Exploitation evidence first, then reachability and business impact."""
    if not 0 <= cvss <= 10 or not 0 <= epss <= 1 or not 1 <= asset_criticality <= 5:
        raise ValueError("Valores de riesgo fuera de rango")
    exploited = kev or epss >= 0.5
    if exploited and (exposure == "public" or asset_criticality >= 4):
        return "critical"
    if exploited or cvss >= 9.0:
        return "high"
    if cvss >= 7.0 or epss >= 0.1:
        return "medium"
    return "low"


PRIORITY_RULE_TEXT = (
    "Prioridad: 'explotación conocida' significa KEV=sí o EPSS>=0.5. "
    "critical si hay explotación conocida y el activo es público o de criticidad>=4; "
    "high si hay explotación conocida (sin lo anterior) o CVSS>=9.0; "
    "medium si CVSS>=7.0 o EPSS>=0.1; low en cualquier otro caso."
)
