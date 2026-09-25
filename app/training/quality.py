"""Small, inspectable quality checks for chat fine-tuning datasets."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any


def _digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _protocol(example: dict[str, Any]) -> str:
    try:
        answer = json.loads(example["messages"][-1]["content"])
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return "invalid"
    if "action_type" in answer:
        return "orchestrator_action"
    if "outcome" in answer:
        return "benchmark_outcome"
    return "other"


def audit_training_splits(splits: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Profile duplicates, protocol mixing and prompt leakage across splits."""
    train = splits.get("train", [])
    fingerprints = [_digest(example.get("messages")) for example in train]
    exact_duplicates = len(fingerprints) - len(set(fingerprints))

    protocols = Counter(_protocol(example) for example in train)
    sources = Counter(str(example.get("meta", {}).get("source", "orchestrator_trace")) for example in train)
    categories = Counter(
        str(example.get("meta", {}).get("category", "uncategorized")) for example in train
    )

    prompt_sets = {
        name: {
            _digest(example.get("messages", [])[:-1])
            for example in examples
            if example.get("messages")
        }
        for name, examples in splits.items()
    }
    overlaps = {}
    names = sorted(prompt_sets)
    for index, first in enumerate(names):
        for second in names[index + 1:]:
            count = len(prompt_sets[first] & prompt_sets[second])
            if count:
                overlaps[f"{first}:{second}"] = count

    total = len(train)
    return {
        "train_examples": total,
        "unique_train_examples": len(set(fingerprints)),
        "exact_duplicates": exact_duplicates,
        "exact_duplicate_rate": exact_duplicates / total if total else 0.0,
        "protocols": dict(sorted(protocols.items())),
        "sources": dict(sorted(sources.items())),
        "categories": dict(sorted(categories.items())),
        "cross_split_prompt_overlaps": overlaps,
    }


def blocking_quality_issues(
    report: dict[str, Any],
    *,
    max_exact_duplicate_rate: float = 0.05,
    allow_mixed_protocols: bool = False,
) -> list[str]:
    issues = []
    rate = report["exact_duplicate_rate"]
    if rate > max_exact_duplicate_rate:
        issues.append(
            f"duplicados exactos {rate:.1%} > límite {max_exact_duplicate_rate:.1%}"
        )
    active_protocols = {
        name for name, count in report["protocols"].items()
        if count and name not in {"invalid", "other"}
    }
    if len(active_protocols) > 1 and not allow_mixed_protocols:
        issues.append("se mezclan protocolos de salida: " + ", ".join(sorted(active_protocols)))
    if report["protocols"].get("invalid"):
        issues.append(f"{report['protocols']['invalid']} respuestas de entrenamiento inválidas")
    if report["cross_split_prompt_overlaps"]:
        issues.append("hay prompts idénticos en más de un split")
    return issues
