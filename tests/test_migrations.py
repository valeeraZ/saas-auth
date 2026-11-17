from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from alembic import command
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from saas_auth.api import create_app
from saas_auth.config import Settings
from saas_auth.db import Database
from saas_auth.db.migrations import at_head, migration_config


@pytest.fixture
def fresh_database(database_url):
    name = "alembic_" + uuid4().hex + "_test"
    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    dsn = make_conninfo(**(conninfo_to_dict(database_url) | {"dbname": name}))
    try:
        yield dsn
    finally:
        with psycopg.connect(database_url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


def upgrade(dsn, revision="head"):
    config = migration_config()
    config.attributes["database_url"] = dsn
    command.upgrade(config, revision)


def test_fresh_upgrade_replay_and_autogenerate(fresh_database):
    upgrade(fresh_database)
    upgrade(fresh_database)
    database = Database(fresh_database)
    try:
        with database.engine.connect() as conn:
            assert at_head(conn)
        config = migration_config()
        config.attributes["database_url"] = fresh_database
        command.check(config)
    finally:
        database.close()
    with psycopg.connect(fresh_database) as conn:
        assert (
            conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            == "004_app_access_requests"
        )
        assert conn.execute("SELECT to_regclass('schema_migrations')").fetchone()[0] is None


def test_ready_requires_alembic_head(fresh_database):
    upgrade(fresh_database, "003_user_app_platform")
    settings = Settings(fresh_database, "https://identity.example.test", "x" * 32)
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/ready").status_code == 503
        upgrade(fresh_database)
        assert client.get("/health/ready").status_code == 200


def test_concurrent_cli_upgrades(fresh_database):
    import os
    import subprocess
    import sys

    environment = os.environ | {"SAAS_DATABASE_URL": fresh_database}
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(Path("alembic.ini").resolve()),
                "upgrade",
                "head",
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    results = [process.communicate(timeout=30) for process in processes]
    assert [process.returncode for process in processes] == [0, 0], results
    with psycopg.connect(fresh_database) as conn:
        assert conn.execute("SELECT count(*) FROM alembic_version").fetchone()[0] == 1


def test_historical_downgrade_fails_without_changing_revision(fresh_database):
    upgrade(fresh_database)
    config = migration_config()
    config.attributes["database_url"] = fresh_database
    with pytest.raises(RuntimeError, match="database restore"):
        command.downgrade(config, "-1")
    database = Database(fresh_database)
    try:
        with database.engine.connect() as connection:
            assert at_head(connection)
    finally:
        database.close()


def test_generated_revision_upgrade_and_downgrade(fresh_database, tmp_path):
    import shutil

    from alembic.script import ScriptDirectory

    upgrade(fresh_database)
    config = migration_config()
    scripts = ScriptDirectory.from_config(config)
    directory = tmp_path / "alembic"
    shutil.copytree(scripts.dir, directory)
    config.set_main_option("script_location", str(directory))
    config.attributes["database_url"] = fresh_database
    revision = command.revision(config, message="Add user note", autogenerate=True)
    assert revision is not None and not isinstance(revision, list)
    path = Path(revision.path)
    content = path.read_text()
    # Give the generated revision a small reversible DDL change.
    content = content.replace(
        "    pass", '    op.add_column("users", sa.Column("note", sa.Text()))', 1
    )
    content = content.replace("    pass", '    op.drop_column("users", "note")', 1)
    path.write_text(content)
    command.upgrade(config, "head")
    with psycopg.connect(fresh_database) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='note'"
            ).fetchone()[0]
            == 1
        )
    command.downgrade(config, "-1")
    with psycopg.connect(fresh_database) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='note'"
            ).fetchone()[0]
            == 0
        )
