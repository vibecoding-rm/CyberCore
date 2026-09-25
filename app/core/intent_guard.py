"""Deterministic preflight checks for targets embedded in operator text.

The LLM may help select a tool, but it must not be the component that decides
whether an explicitly named target is in scope. This module also unwraps
small, printable Base64 fragments so trivial encoding cannot hide a target
from the policy engine.

This is a heuristic early refusal, not the security boundary: it only sees
literal IPv4 addresses that closely follow an operation word, so it misses
hostnames and paraphrases. The ToolBroker validates every structured tool
argument against the policy before execution, whatever this guard decided.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass

from app.core.policy import PolicyEngine


_IPV4_TARGET = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
# Words that make a nearby address the object of an operation.
_OPERATION_WORD = re.compile(
    r"\b(?:escane\w*|inspeccion\w*|descubr\w*|ejecut\w*|lanz\w*|explot\w*|"
    r"valid\w*|consult\w*|obt[eé]n\w*|revis\w*|analiz\w*|audit\w*|comprueb\w*|"
    r"comprob\w*|prueb\w*|sonde\w*|enumer\w*|atac\w*|ataque|ping|nmap|nuclei|"
    r"greenbone|puertos?|servicios?|fuzzing|fuerza\s+bruta|webshell|"
    r"scan\w*|inspect\w*|discover\w*|run|exploit\w*|check|probe|test|analy[sz]e)\b",
    re.IGNORECASE,
)
# A dotted quad right after one of these words is a software version.
_VERSION_PREFIX = re.compile(r"(?:\bversi[oó]n|\bversion|\bv)\s*:?\s*$", re.IGNORECASE)
# How many words before an address may hold the operation word.
OPERATION_WINDOW_WORDS = 8
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


def _is_address(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    return True


def _requests_operation_on(text: str, start: int) -> bool:
    """True when an operation word appears among the words just before start."""
    preceding = " ".join(text[:start].split()[-OPERATION_WINDOW_WORDS:])
    return _OPERATION_WORD.search(preceding) is not None


def inspect_intent_scope(intent: str, policy: PolicyEngine) -> IntentScopeInspection:
    """Find literal IPv4/CIDR targets and return any scope violations."""
    decoded = _decode_base64_fragments(intent)
    targets: list[str] = []
    actionable_targets: list[str] = []
    for text in [intent, *decoded]:
        for match in _IPV4_TARGET.finditer(text):
            target = match.group(0)
            if not _is_address(target) or _VERSION_PREFIX.search(text[:match.start()]):
                continue
            if target not in targets:
                targets.append(target)
            if _requests_operation_on(text, match.start()) and target not in actionable_targets:
                actionable_targets.append(target)

    violations = []
    for target in actionable_targets:
        reason = policy.validate_scope(target)
        if reason is not None:
            violations.append(reason)

    return IntentScopeInspection(tuple(targets), tuple(decoded), tuple(violations))
