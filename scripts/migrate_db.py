from pathlib import Path
import sys

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.settings import get_settings


MIGRATIONS_DIR = Path(__file__).parents[1] / "db" / "migrations"


def apply_migrations() -> None:
    settings = get_settings()
    with psycopg.connect(
        settings.database_url,
        connect_timeout=settings.database_connect_timeout_seconds,
    ) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )

        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            version = path.stem
            already_applied = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = %s",
                (version,),
            ).fetchone()
            if already_applied:
                continue

            with connection.transaction():
                connection.execute(path.read_text(encoding="utf-8"))
                connection.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)",
                    (version,),
                )
            print(f"Migración aplicada: {version}")


if __name__ == "__main__":
    apply_migrations()
