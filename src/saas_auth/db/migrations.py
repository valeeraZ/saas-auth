from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection


def migration_config() -> Config:
    """Resolve packaged revisions independently of the caller's working directory."""
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "alembic"))
    return config


def at_head(connection: Connection) -> bool:
    current = set(MigrationContext.configure(connection).get_current_heads())
    expected = set(ScriptDirectory.from_config(migration_config()).get_heads())
    return current == expected
