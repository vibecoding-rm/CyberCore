"""Audit a training dataset before spending GPU time.

    python -m scripts.audit_training_dataset data/training/v6
"""

import argparse
import json
from pathlib import Path

from app.training.quality import audit_training_splits, blocking_quality_issues


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--max-exact-duplicate-rate", type=float, default=0.05)
    parser.add_argument("--allow-mixed-protocols", action="store_true")
    args = parser.parse_args()

    splits = {
        name: read_jsonl(args.dataset / f"{name}.jsonl")
        for name in ("train", "validation", "test")
    }
    report = audit_training_splits(splits)
    issues = blocking_quality_issues(
        report,
        max_exact_duplicate_rate=args.max_exact_duplicate_rate,
        allow_mixed_protocols=args.allow_mixed_protocols,
    )
    print(json.dumps(report | {"accepted": not issues, "issues": issues}, ensure_ascii=False, indent=2))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
