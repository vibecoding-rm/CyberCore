"""Deterministic preflight checks for targets embedded in operator text.

The LLM may help select a tool, but it must not be the component that decides
whether an explicitly named target is in scope. This module also unwraps
small, printable Base64 fragments so trivial encoding cannot hide a target
from the policy engine.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from app.core.policy import PolicyEngine


_IPV4_TARGET = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_OPERATION_REQUEST = re.compile(
    r"\b(?:escane(?:a|ar)|inspeccion(?:a|ar)|descubr(?:e|ir)|ejecut(?:a|ar)|"
    r"lanz(?:a|ar)|explot(?:a|ar)|valid(?:a|ar)|consult(?:a|ar)|obt[eé]n|"
    r"fuzzing|fuerza\s+bruta|webshell|scan|inspect|discover|run|exploit)\b",
    re.IGNORECASE,
)
MAX_DECODED_BYTES = 4096
MAX_DECODE_DEPTH = 2


@dataclass(frozen=True)
class IntentScopeInspection:
    targets: tuple[str, ...]
    decoded_fragments: tuple[str, ...]
    violations: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return not self.violations


def _printable_text(raw: bytes) -> str | None:
    if not raw or len(raw) > MAX_DECODED_BYTES:
        return None
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character.isspace() for character in value)
    if printable / len(value) < 0.9:
        return None
    return value.strip() or None


def _decode_base64_fragments(value: str) -> list[str]:
    decoded: list[str] = []
    frontier = [value]
    seen = {value}
    for _ in range(MAX_DECODE_DEPTH):
        next_frontier: list[str] = []
        for text in frontier:
            for match in _BASE64_TOKEN.finditer(text):
                token = match.group(0)
                padded = token + "=" * (-len(token) % 4)
                try:
                    raw = base64.b64decode(padded, validate=True)
                except (binascii.Error, ValueError):
                    continue
                fragment = _printable_text(raw)
                if fragment is None or fragment in seen:
                    continue
                seen.add(fragment)
                decoded.append(fragment)
                next_frontier.append(fragment)
        frontier = next_frontier
        if not frontier:
            break
    return decoded


def inspect_intent_scope(intent: str, policy: PolicyEngine) -> IntentScopeInspection:
    """Find literal IPv4/CIDR targets and return any scope violations."""
    decoded = _decode_base64_fragments(intent)
    targets: list[str] = []
    actionable_targets: list[str] = []
    for text in [intent, *decoded]:
        for match in _IPV4_TARGET.finditer(text):
            target = match.group(0)
            if target not in targets:
                targets.append(target)
            if _OPERATION_REQUEST.search(text) and target not in actionable_targets:
                actionable_targets.append(target)

    violations = []
    for target in actionable_targets:
        reason = policy.validate_scope(target)
        if reason is not None:
            violations.append(reason)

    return IntentScopeInspection(tuple(targets), tuple(decoded), tuple(violations))
