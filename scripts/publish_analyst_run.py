"""Publish an Analyst-Bench run so reviewers can score it at /analyst-review.

    python -m scripts.publish_analyst_run reports/analyst/runs/<run>.json

Runs are append-only: a published run cannot be replaced, only a new one
with another run id can be published.
"""

import argparse
import asyncio
from pathlib import Path

from app.analyst.bench import AnalystRun
from app.event_loop import psycopg_compatible_loop
from app.settings import get_settings
from app.storage.postgres_analyst_bench import PostgresAnalystBenchRepository


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run", type=Path)
    args = parser.parse_args()

    run = AnalystRun.model_validate_json(args.run.read_text(encoding="utf-8"))
    settings = get_settings()
    repository = PostgresAnalystBenchRepository(
        settings.database_url, settings.database_connect_timeout_seconds
    )
    asyncio.run(repository.publish_run(run), loop_factory=psycopg_compatible_loop)
    reviewable = sum(
        answer.passed_gate for result in run.results for answer in result.answers.values()
    )
    print(f"Publicada {run.run_id}: {len(run.results)} casos, {reviewable} respuestas a puntuar")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
