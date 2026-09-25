"""Mix an orchestrator dataset with replay examples from CyberCAM-Bench.

    python -m scripts.build_mixed_dataset --orchestrator v4 \
        --replay-report reports/benchmarks/<base-model train report>.json --name v5         [--replay-weight 2 --category-weight finding_status=4]

Adapter v4, trained only on orchestration, forgot analyst skills and was
rejected by the CyberCAM-Bench gate. Replay examples keep them: the base
model's own answers on the benchmark's *train* split that the benchmark's
deterministic checks marked as correct. Only the train split is accepted,
so the test split used by the gate never leaks into training.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.evaluation.benchmark import (
    BenchmarkReport,
    BenchmarkRunner,
    BenchmarkSuite,
    answer_generation_schema,
)

OUTPUT_ROOT = Path("data/training")
BENCHMARK = Path("config/benchmark_cybercam.yaml")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def variant_fields() -> dict[str, list[str]]:
    """Field order the grammar-constrained model emits for each outcome."""
    return {
        variant["properties"]["outcome"]["const"]: list(variant["properties"])
        for variant in answer_generation_schema()["oneOf"]
    }


def replay_examples(report: BenchmarkReport, suite: BenchmarkSuite) -> list[dict[str, Any]]:
    cases = {case.id: case for case in suite.cases}
    order = variant_fields()
    schema = answer_generation_schema()
    examples = []
    for result in report.results:
        if not result.passed or result.answer is None:
            continue
        case = cases[result.case_id]
        if case.split != "train":
            raise SystemExit(f"{case.id} no es del split train; no se usa para entrenar")
        answer = result.answer.model_dump(mode="json")
        target = {name: answer.get(name) for name in order[answer["outcome"]]}
        messages = BenchmarkRunner._messages(case, schema)
        messages.append({"role": "assistant", "content": json.dumps(target, ensure_ascii=False)})
        examples.append({
            "messages": messages,
            "meta": {"source": "replay", "case_id": case.id, "category": case.category},
        })
    return examples


def parse_weights(values: list[str]) -> dict[str, int]:
    weights = {}
    for value in values:
        category, _, count = value.partition("=")
        if not category or not count.isdigit() or int(count) < 1:
            raise SystemExit(f"Peso inválido {value!r}; formato categoria=N con N >= 1")
        weights[category] = int(count)
    return weights


def weighted(examples: list[dict[str, Any]], default: int, weights: dict[str, int]) -> list[dict[str, Any]]:
    """Repeat each replay example by its category weight (train split only)."""
    return [
        example
        for example in examples
        for _ in range(weights.get(example["meta"]["category"], default))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--orchestrator", required=True, help="Dataset de orquestación ya exportado")
    parser.add_argument("--replay-report", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--validation-every", type=int, default=10,
                        help="1 de cada N ejemplos de repaso va a validation")
    parser.add_argument("--replay-weight", type=int, default=1,
                        help="Repeticiones de cada ejemplo de repaso en train")
    parser.add_argument("--category-weight", action="append", default=[], metavar="CATEGORIA=N",
                        help="Repeticiones en train para una categoría (sustituye a --replay-weight)")
    args = parser.parse_args()

    source = OUTPUT_ROOT / args.orchestrator
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    for name, info in manifest["files"].items():
        if sha256_file(source / name) != info["sha256"]:
            raise SystemExit(f"{source / name}: el hash no coincide con su manifiesto")
    output = OUTPUT_ROOT / args.name
    if output.exists():
        print(f"{output} ya existe; los datasets son inmutables", file=sys.stderr)
        return 1

    report = BenchmarkReport.model_validate_json(args.replay_report.read_text(encoding="utf-8"))
    if report.split != "train":
        raise SystemExit(f"El informe es del split {report.split!r}; sólo se admite 'train'")
    replay = replay_examples(report, BenchmarkSuite.from_yaml(BENCHMARK))
    if args.replay_weight < 1:
        raise SystemExit("--replay-weight debe ser >= 1")
    weights = parse_weights(args.category_weight)

    splits = {name: read_jsonl(source / f"{name}.jsonl") for name in ("train", "validation", "test")}
    replay_train = []
    for i, example in enumerate(sorted(replay, key=lambda e: e["meta"]["case_id"])):
        if i % args.validation_every == 0:
            splits["validation"].append(example)
        else:
            replay_train.append(example)
    splits["train"].extend(weighted(replay_train, args.replay_weight, weights))

    output.mkdir(parents=True)
    files = {}
    for name, examples in splits.items():
        path = output / f"{name}.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for example in examples:
                handle.write(json.dumps(example, ensure_ascii=False) + "\n")
        files[path.name] = {"examples": len(examples), "sha256": sha256_file(path)}

    mixed = {
        "name": args.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "orchestrator": {"dataset": args.orchestrator, "manifest": manifest["files"]},
            "replay": {
                "report": str(args.replay_report).replace("\\", "/"),
                "report_sha256": sha256_file(args.replay_report),
                "model": report.model,
                "split": report.split,
                "examples": len(replay),
                "train_weight": args.replay_weight,
                "category_weights": weights,
                "benchmark_sha256": sha256_file(BENCHMARK),
            },
        },
        "license": manifest.get("license"),
        "files": files,
    }
    (output / "manifest.json").write_text(json.dumps(mixed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{args.name}: {len(replay)} ejemplos de repaso + {args.orchestrator} -> {output}")
    print({name: info["examples"] for name, info in files.items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
