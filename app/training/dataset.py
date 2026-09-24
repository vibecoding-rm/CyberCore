"""Build a QLoRA dataset from reviewed orchestrator traces (docs/05, steps 2-5).

Input: traces whose latest human review is `approved`, with that review.
Output: chat examples {"messages": [...], "meta": {...}} split into
train / validation / test by *family*, plus the numbers for the manifest.

Rules, in order:
  - Only approved traces are read; the caller guarantees it and build_dataset
    rejects anything else.
  - Target of a step = the reviewer's correction if any, else the model's raw
    output. It must validate as AgentThoughtAndAction and is re-serialized
    canonically; steps whose output is invalid and uncorrected are dropped.
  - After a corrected step the later steps are dropped: their history was
    built from the action the model actually took, not from the correction.
  - Sanitization replaces non-lab IP addresses (keeping whether they were in
    scope), hostnames, e-mail addresses and credential-like strings. The
    system prompt is ours and is not sanitized; when `system_prompt` is given
    it replaces the one recorded in the trace, so every example is trained
    with the prompt the model will actually receive (targets are reviewed
    answers, valid under the current rules).
  - With `drop_out_of_scope_calls`, a target that calls a tool on an address
    outside the scope is dropped: the prompt now states the scope and says
    not to call it.
  - Exact duplicates are merged; identical inputs with different targets are
    ambiguous and all dropped.
  - Families (normalized operator intent) never cross splits, and intents that
    match a CyberCAM-Bench prompt are excluded so the benchmark stays clean.
"""

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any, Callable, Iterable

from pydantic import ValidationError

from app.agent.models import AgentThoughtAndAction
from app.agent.traces import AgentTrace, TraceReview

# v2: out-of-scope private addresses keep looking private (10.255.0.x);
# v1 mapped them to 203.0.113.x, which reads as a public address.
SANITIZER_VERSION = 2
SPLITS = ("train", "validation", "test")

# Lab and documentation ranges carry no information about a real network.
LAB_NETWORKS = [
    IPv4Network("127.0.0.0/8"),
    IPv4Network("192.168.10.0/24"),
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
]
IN_SCOPE_PLACEHOLDER = IPv4Network("192.168.10.0/24")
# Out of scope: keep private addresses private and public ones public, since
# the orchestrator must treat "public Internet" differently from "internal but
# not authorized".
OUT_OF_SCOPE_PRIVATE_PLACEHOLDER = IPv4Network("10.255.0.0/24")
OUT_OF_SCOPE_PUBLIC_PLACEHOLDER = IPv4Network("203.0.113.0/24")

# A trailing sentence period is fine; a dot followed by a digit is not.
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?!\d|\.\d)")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_HOSTNAME = re.compile(r"(Hostname:\s*)(?!desconocido\b)([A-Za-z0-9][\w.-]*)")
_SECRET = re.compile(
    r"(?i)(bearer\s+|(?:api[_-]?key|token|password|passwd|secret)\s*[:=]\s*)[^\s,;'\"}]+"
)


@dataclass
class DatasetStats:
    approved_traces: int = 0
    steps_seen: int = 0
    kept: int = 0
    dropped: Counter = field(default_factory=Counter)
    per_split: Counter = field(default_factory=Counter)
    families_per_split: dict[str, int] = field(default_factory=dict)
    system_prompt_replaced: int = 0


class TraceSanitizer:
    """Consistent replacements within one trace (same address -> same pseudonym)."""

    def __init__(self, in_scope: Callable[[str], bool]):
        self.in_scope = in_scope
        self.addresses: dict[str, str] = {}
        self.hostnames: dict[str, str] = {}
        self._next: dict[IPv4Network, int] = {}

    def __call__(self, text: str) -> str:
        text = _SECRET.sub(lambda m: m.group(1) + "[REDACTADO]", text)
        text = _EMAIL.sub("usuario@example.org", text)
        text = _HOSTNAME.sub(lambda m: m.group(1) + self._hostname(m.group(2)), text)
        return _IPV4.sub(self._address, text)

    def _hostname(self, name: str) -> str:
        return self.hostnames.setdefault(name, f"host-{len(self.hostnames) + 1:02d}")

    def _address(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            parsed = ip_network(raw, strict=False) if match.group(2) else ip_address(match.group(1))
        except ValueError:
            return raw
        base = parsed.network_address if isinstance(parsed, IPv4Network) else parsed
        if not isinstance(base, IPv4Address) or any(base in net for net in LAB_NETWORKS):
            return raw
        if raw not in self.addresses:
            if self.in_scope(raw):
                placeholder = IN_SCOPE_PLACEHOLDER
            elif base.is_private:
                placeholder = OUT_OF_SCOPE_PRIVATE_PLACEHOLDER
            else:
                placeholder = OUT_OF_SCOPE_PUBLIC_PLACEHOLDER
            if isinstance(parsed, IPv4Network):
                # Never widen: a pseudonymized network is at most a /24.
                self.addresses[raw] = f"{placeholder.network_address}/{max(parsed.prefixlen, 24)}"
            else:
                host = self._next.get(placeholder, 10)
                self._next[placeholder] = host + 1
                if host > 254:
                    raise ValueError("Demasiadas direcciones distintas en una traza")
                self.addresses[raw] = str(placeholder.network_address + host)
        return self.addresses[raw]


def normalize_intent(text: str) -> str:
    """Family key: case, addresses, numbers and punctuation do not matter."""
    text = _IPV4.sub(" IP ", text.casefold())
    text = re.sub(r"\d+", " N ", text)
    text = re.sub(r"[^\w]+", " ", text)
    return " ".join(text.split())


def split_for_family(family: str) -> str:
    bucket = int(hashlib.sha256(family.encode()).hexdigest(), 16) % 10
    return "test" if bucket == 0 else "validation" if bucket == 1 else "train"


def canonical_target(raw: str | AgentThoughtAndAction) -> str:
    action = raw if isinstance(raw, AgentThoughtAndAction) else AgentThoughtAndAction.model_validate_json(raw)
    return json.dumps(action.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)


def _calls_out_of_scope(target: str, in_scope: Callable[[str], bool]) -> bool:
    action = json.loads(target)
    if action.get("action_type") != "call_tool":
        return False
    address = (action.get("arguments") or {}).get("target")
    return not (isinstance(address, str) and in_scope(address))


def build_dataset(
    reviewed: Iterable[tuple[AgentTrace, TraceReview]],
    in_scope: Callable[[str], bool],
    excluded_intents: Iterable[str] = (),
    system_prompt: str | None = None,
    drop_out_of_scope_calls: bool = False,
) -> tuple[dict[str, list[dict[str, Any]]], DatasetStats]:
    stats = DatasetStats()
    excluded = {normalize_intent(intent) for intent in excluded_intents}
    candidates: list[tuple[str, str, dict[str, Any]]] = []  # (family, input_key, example)

    for trace, review in reviewed:
        if review.run_id != trace.run_id or review.verdict != "approved":
            raise ValueError(f"La traza {trace.run_id} no está aprobada")
        stats.approved_traces += 1
        family = normalize_intent(trace.operator_intent)
        if family in excluded:
            stats.dropped["benchmark_overlap"] += len(trace.steps)
            continue
        sanitize = TraceSanitizer(in_scope)
        for step in sorted(trace.steps, key=lambda s: s.step_number):
            stats.steps_seen += 1
            correction = review.corrections.get(step.step_number)
            try:
                target = canonical_target(correction or step.raw_output or "")
            except (ValidationError, ValueError):
                stats.dropped["invalid_output"] += 1
                continue
            if drop_out_of_scope_calls and _calls_out_of_scope(target, in_scope):
                # Reviewed before the prompt stated the scope ("call it and
                # let the policy decide"); now the prompt says not to call.
                stats.dropped["out_of_scope_call"] += 1
                if correction is not None:
                    later = [s for s in trace.steps if s.step_number > step.step_number]
                    stats.steps_seen += len(later)
                    stats.dropped["after_correction"] += len(later)
                    break
                continue
            messages = []
            for message in step.messages:
                if message["role"] != "system":
                    messages.append({**message, "content": sanitize(message["content"])})
                elif system_prompt is not None and message["content"] != system_prompt:
                    messages.append({**message, "content": system_prompt})
                    stats.system_prompt_replaced += 1
                else:
                    messages.append(message)
            messages.append({"role": "assistant", "content": sanitize(target)})
            input_key = json.dumps(messages[:-1], ensure_ascii=False, sort_keys=True)
            candidates.append((family, input_key, {
                "messages": messages,
                "meta": {
                    "run_id": str(trace.run_id),
                    "step_number": step.step_number,
                    "corrected": correction is not None,
                    "family": hashlib.sha256(family.encode()).hexdigest()[:16],
                },
            }))
            if correction is not None:
                later = [s for s in trace.steps if s.step_number > step.step_number]
                stats.steps_seen += len(later)
                stats.dropped["after_correction"] += len(later)
                break

    targets_by_input: dict[str, set[str]] = {}
    for _, input_key, example in candidates:
        targets_by_input.setdefault(input_key, set()).add(example["messages"][-1]["content"])

    splits: dict[str, list[dict[str, Any]]] = {name: [] for name in SPLITS}
    families: dict[str, set[str]] = {name: set() for name in SPLITS}
    seen: set[tuple[str, str]] = set()
    for family, input_key, example in candidates:
        target = example["messages"][-1]["content"]
        if len(targets_by_input[input_key]) > 1:
            stats.dropped["ambiguous"] += 1
            continue
        if (input_key, target) in seen:
            stats.dropped["duplicate"] += 1
            continue
        seen.add((input_key, target))
        split = split_for_family(family)
        splits[split].append(example)
        families[split].add(family)

    stats.kept = sum(len(examples) for examples in splits.values())
    stats.per_split = Counter({name: len(examples) for name, examples in splits.items()})
    stats.families_per_split = {name: len(values) for name, values in families.items()}
    return splits, stats
