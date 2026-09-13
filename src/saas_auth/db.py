import hashlib
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


def make_pool(database_url: str):
    return ConnectionPool(
        database_url,
        min_size=1,
        max_size=8,
        timeout=5,
        open=False,
        kwargs={
            "row_factory": dict_row,
            "connect_timeout": 5,
            "options": "-c statement_timeout=5000 -c lock_timeout=3000",
        },
        check=ConnectionPool.check_connection,
    )


def migrate(database_url: str, directory: Path | None = None):
    """Ordered, checksummed migrations; no implicit schema changes on API startup."""
    directory = directory or Path(__file__).parent / "migrations"
    with psycopg.connect(database_url) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(72401102)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(name text PRIMARY KEY, sha256 text NOT NULL, "
            "applied_at timestamptz NOT NULL DEFAULT now())"
        )
        for path in sorted(directory.glob("*.sql")):
            sql = path.read_text()
            digest = hashlib.sha256(sql.encode()).hexdigest()
            previous = conn.execute(
                "SELECT sha256 FROM schema_migrations WHERE name=%s", (path.name,)
            ).fetchone()
            if previous:
                if previous[0] != digest:
                    raise RuntimeError("Applied migration checksum mismatch: " + path.name)
                continue
            conn.execute(sql)
            conn.execute(
                "INSERT INTO schema_migrations(name,sha256) VALUES (%s,%s)", (path.name, digest)
            )
