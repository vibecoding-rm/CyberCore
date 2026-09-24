"""Export approved orchestrator traces as a QLoRA dataset (docs/05).

    python -m scripts.export_training_dataset --name v1

Writes data/training/<name>/{train,validation,test}.jsonl and manifest.json.
The output is ignored by git: even sanitized, it derives from real operations.
"""

import argparse
import asyncio
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.agent.prompts import render_system_prompt
from app.core.policy import PolicyEngine
from app.event_loop import psycopg_compatible_loop
from app.evaluation.benchmark import BenchmarkSuite
from app.settings import get_settings
from app.storage.postgres_traces import PostgresTraceRepository
from app.training.dataset import SANITIZER_VERSION, SPLITS, build_dataset

OUTPUT_ROOT = Path("data/training")
BENCHMARK = Path("config/benchmark_cybercam.yaml")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def load_reviewed(repo: PostgresTraceRepository):
    reviewed = []
    for run_id in await repo.approved_run_ids():
        review = await repo.latest_review(run_id)
        # Re-checked here so a review added meanwhile cannot slip through.
        if review is not None and review.verdict == "approved":
            reviewed.append((await repo.get(run_id), review))
    return reviewed


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--name", required=True, help="Versión del dataset, p. ej. v1")
    parser.add_argument("--min-examples", type=int, default=1)
    args = parser.parse_args()

    output = OUTPUT_ROOT / args.name
    if output.exists():
        print(f"{output} ya existe; los datasets son inmutables, usa otro --name", file=sys.stderr)
        return 1

    settings = get_settings()
    policy = PolicyEngine(settings.policy_file)
    repo = PostgresTraceRepository(settings.database_url, settings.database_connect_timeout_seconds)
    reviewed = await load_reviewed(repo)
    system_prompt = render_system_prompt(policy)
    benchmark_prompts = [case.prompt for case in BenchmarkSuite.from_yaml(BENCHMARK).cases]

    splits, stats = build_dataset(
        reviewed,
        in_scope=lambda target: policy._validate_scope(target) is None,
        excluded_intents=benchmark_prompts,
        system_prompt=system_prompt,
        drop_out_of_scope_calls=True,
    )
    if stats.kept < args.min_examples:
        print(
            f"Sólo {stats.kept} ejemplos (mínimo {args.min_examples}); no se escribe nada. "
            f"Trazas aprobadas: {stats.approved_traces}, descartes: {dict(stats.dropped)}",
            file=sys.stderr,
        )
        return 2

    output.mkdir(parents=True)
    files = {}
    for name in SPLITS:
        path = output / f"{name}.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for example in splits[name]:
                handle.write(json.dumps(example, ensure_ascii=False) + "\n")
        files[path.name] = {"examples": len(splits[name]), "sha256": sha256_file(path)}

    manifest = {
        "name": args.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "agent_runs/agent_steps con última revisión 'approved'",
        "license": "Uso interno; derivado de operaciones propias, no redistribuir",
        "sanitizer_version": SANITIZER_VERSION,
        "system_prompt_sha256": hashlib.sha256(system_prompt.encode()).hexdigest(),
        "policy_sha256": sha256_file(Path(settings.policy_file)),
        "benchmark_sha256": sha256_file(BENCHMARK),
        "system_prompt_replaced": stats.system_prompt_replaced,
        "approved_traces": stats.approved_traces,
        "steps_seen": stats.steps_seen,
        "dropped": dict(stats.dropped),
        "families_per_split": stats.families_per_split,
        "run_ids": sorted(str(trace.run_id) for trace, _ in reviewed),
        "files": files,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"{stats.kept} ejemplos -> {output}")
    print("por split:", dict(stats.per_split), "descartes:", dict(stats.dropped))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(), loop_factory=psycopg_compatible_loop))
