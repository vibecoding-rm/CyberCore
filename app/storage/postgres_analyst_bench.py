import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.analyst.bench import CRITERIA, AnalystRun, RubricScores, ScoreInput, StoredScore


class AnalystBenchStoreError(RuntimeError):
    pass


class AnalystRunNotFoundError(LookupError):
    pass


class DuplicateScoreError(ValueError):
    pass


class PostgresAnalystBenchRepository:
    def __init__(self, database_url: str, connect_timeout_seconds: int = 3):
        if connect_timeout_seconds <= 0:
            raise ValueError("El timeout de conexión debe ser positivo")
        self.database_url = database_url
        self.connect_timeout_seconds = connect_timeout_seconds

    async def publish_run(self, run: AnalystRun) -> None:
        try:
            async with await self._connect() as connection:
                await connection.execute(
                    "INSERT INTO analyst_bench_runs (run_id, split, payload) VALUES (%s, %s, %s)",
                    (run.run_id, run.split, Jsonb(run.model_dump(mode="json"))),
                )
        except psycopg.errors.UniqueViolation as exc:
            raise ValueError(f"La ejecución {run.run_id} ya está publicada") from exc
        except psycopg.Error as exc:
            raise AnalystBenchStoreError("No se pudo publicar la ejecución") from exc

    async def list_runs(self) -> list[AnalystRun]:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    "SELECT payload FROM analyst_bench_runs ORDER BY published_at DESC"
                )
                rows = await cursor.fetchall()
        except psycopg.Error as exc:
            raise AnalystBenchStoreError("No se pudieron listar las ejecuciones") from exc
        return [AnalystRun.model_validate(row["payload"]) for row in rows]

    async def get_run(self, run_id: str) -> AnalystRun:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    "SELECT payload FROM analyst_bench_runs WHERE run_id = %s", (run_id,)
                )
                row = await cursor.fetchone()
        except psycopg.Error as exc:
            raise AnalystBenchStoreError("No se pudo leer la ejecución") from exc
        if row is None:
            raise AnalystRunNotFoundError(run_id)
        return AnalystRun.model_validate(row["payload"])

    async def add_score(self, run_id: str, reviewer: str, score: ScoreInput) -> StoredScore:
        values = score.scores.model_dump()
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    f"""
                    INSERT INTO analyst_bench_scores (
                        run_id, case_id, answer_id, reviewer, {", ".join(CRITERIA)}, comment
                    ) VALUES (%s, %s, %s, %s, {", ".join(["%s"] * len(CRITERIA))}, %s)
                    RETURNING scored_at
                    """,
                    (run_id, score.case_id, score.answer_id, reviewer,
                     *(values[c] for c in CRITERIA), score.comment),
                )
                row = await cursor.fetchone()
        except psycopg.errors.UniqueViolation as exc:
            raise DuplicateScoreError("Ya puntuaste esta respuesta") from exc
        except psycopg.Error as exc:
            raise AnalystBenchStoreError("No se pudo guardar la puntuación") from exc
        return StoredScore(**score.model_dump(), reviewer=reviewer, scored_at=row["scored_at"])

    async def scores(self, run_id: str) -> list[StoredScore]:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    f"""
                    SELECT case_id, answer_id, reviewer, {", ".join(CRITERIA)}, comment, scored_at
                    FROM analyst_bench_scores WHERE run_id = %s ORDER BY id
                    """,
                    (run_id,),
                )
                rows = await cursor.fetchall()
        except psycopg.Error as exc:
            raise AnalystBenchStoreError("No se pudieron leer las puntuaciones") from exc
        return [
            StoredScore(
                case_id=row["case_id"], answer_id=row["answer_id"], reviewer=row["reviewer"],
                scores=RubricScores(**{c: row[c] for c in CRITERIA}),
                comment=row["comment"], scored_at=row["scored_at"],
            )
            for row in rows
        ]

    async def _connect(self) -> psycopg.AsyncConnection:
        return await psycopg.AsyncConnection.connect(
            self.database_url,
            connect_timeout=self.connect_timeout_seconds,
            row_factory=dict_row,
        )
