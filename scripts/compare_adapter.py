"""Accept or reject a fine-tuned adapter against the unadapted baseline.

    python -m scripts.compare_adapter reports/base-test.json reports/adapter-test.json

Both reports must come from scripts.run_model_benchmark on the same suite and
split. Exit code 0 = accepted, 1 = rejected.
"""

import argparse
import json
from pathlib import Path

from app.evaluation.benchmark import BenchmarkReport
from app.evaluation.gate import evaluate_adapter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()

    baseline = BenchmarkReport.model_validate_json(args.baseline.read_text(encoding="utf-8"))
    candidate = BenchmarkReport.model_validate_json(args.candidate.read_text(encoding="utf-8"))
    result = evaluate_adapter(baseline, candidate)

    print(json.dumps({
        "accepted": result.accepted,
        "baseline": f"{baseline.passed_cases}/{baseline.total_cases}",
        "candidate": f"{candidate.passed_cases}/{candidate.total_cases}",
        "improved": result.improved,
        "regressed": result.regressed,
        "inherited_forbidden_claims": result.inherited_forbidden_claims,
        "reasons": result.reasons,
    }, ensure_ascii=False, indent=2))
    return 0 if result.accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
