"""Import a reviewer's Analyst-Bench scores from a file into the database.

Used when a review was done against another database (for example a cloud
session scoring a run): the file keeps the scores in git and this loads them
into the database that holds the published run. Scores are append-only, so an
answer this reviewer already scored is skipped, not replaced.

    python -m scripts.import_analyst_scores reports/analyst/scores/<run>-<reviewer>.json

File format: {"run_id": ..., "reviewer": ..., "scores": [ScoreInput, ...]}
"""

import argparse
import asyncio
import json
from pathlib import Path

from app.analyst.bench import ScoreInput, reviewable_answer
from app.event_loop import psycopg_compatible_loop
from app.settings import get_settings
from app.storage.postgres_analyst_bench import DuplicateScoreError, PostgresAnalystBenchRepository


async def import_scores(repository: PostgresAnalystBenchRepository, payload: dict) -> tuple[int, int]:
    run = await repository.get_run(payload["run_id"])
    scores = [ScoreInput.model_validate(item) for item in payload["scores"]]
    for score in scores:
        if not reviewable_answer(run, score.case_id, score.answer_id):
            raise SystemExit(f"{score.case_id}/{score.answer_id}: no es una respuesta puntuable")
    added = skipped = 0
    for score in scores:
        try:
            await repository.add_score(run.run_id, payload["reviewer"], score)
            added += 1
        except DuplicateScoreError:
            skipped += 1
    return added, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", type=Path)
    args = parser.parse_args()

    payload = json.loads(args.file.read_text(encoding="utf-8"))
    settings = get_settings()
    repository = PostgresAnalystBenchRepository(
        settings.database_url, settings.database_connect_timeout_seconds
    )
    added, skipped = asyncio.run(import_scores(repository, payload), loop_factory=psycopg_compatible_loop)
    print(f"{payload['reviewer']}: {added} puntuaciones importadas, {skipped} ya existían")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
