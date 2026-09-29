"""Comparative Analyst-Bench report: automatic gate, rubric and adoption criteria.

Adoption is reported under protocol v1 (the model's own answers) and v2 (the
answer the operator receives: the model's, or C0 when the gate suspends it).

    python -m scripts.analyst_bench_report <run_id>
    python -m scripts.analyst_bench_report --file reports/analyst/runs/<run>.json

With --file (no database) only the automatic gate and latency are reported.
The JSON is also written to reports/analyst/<run_id>-report.json.
"""

import argparse
import asyncio
import json
from pathlib import Path

from app.analyst.bench import AnalystRun, build_report
from app.event_loop import psycopg_compatible_loop
from app.settings import get_settings
from app.storage.postgres_analyst_bench import PostgresAnalystBenchRepository

REPORTS_DIR = Path("reports/analyst")


async def load(run_id: str):
    settings = get_settings()
    repository = PostgresAnalystBenchRepository(
        settings.database_url, settings.database_connect_timeout_seconds
    )
    return await repository.get_run(run_id), await repository.scores(run_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    if args.file:
        run, scores = AnalystRun.model_validate_json(args.file.read_text(encoding="utf-8")), []
    elif args.run_id:
        run, scores = asyncio.run(load(args.run_id), loop_factory=psycopg_compatible_loop)
    else:
        raise SystemExit("Indica un run_id publicado o --file")

    report = build_report(run, scores)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    target = REPORTS_DIR / f"{run.run_id}-report.json"
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    for name, system in report["systems"].items():
        print(
            f"{name} ({system['info'].get('model') or system['info']['kind']}): puerta "
            f"{system['gate_passed']}/{system['cases']}, puntuados {system['scored_cases']}, "
            f"media {system['mean_total']}, latencia media {system['mean_latency_ms']} ms"
        )
    for name, verdict in report["adoption"].items():
        state = "cumple" if verdict["meets_criteria"] else "no cumple"
        print(f"{name}: {state} el criterio de adopción v1 (modelo)"
              f"{'' if verdict['complete'] else ' (revisión incompleta)'}: {verdict['reasons']}")
    for name, verdict in report["adoption_pipeline"].items():
        pipeline = report["pipeline"][name]
        state = "cumple" if verdict["meets_criteria"] else "no cumple"
        print(f"{name}: {state} el criterio de adopción v2 (sistema, respaldo en C0 en "
              f"{len(pipeline['fallback_to_c0'])} casos, media {pipeline['mean_total']})"
              f"{'' if verdict['complete'] else ' (revisión incompleta)'}: {verdict['reasons']}")
    print(f"Informe: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
