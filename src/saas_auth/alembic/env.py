import os

from alembic import context
from sqlalchemy import func, select
from sqlalchemy.engine import Connection

from saas_auth.db.database import Database
from saas_auth.db.models import Base

config = context.config
target_metadata = Base.metadata


def run_online(connection: Connection) -> None:
    with connection.begin():
        # Serialize migration discovery and DDL across concurrent deployments.
        connection.execute(select(func.pg_advisory_xact_lock(72401102)))
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        context.run_migrations()


if context.is_offline_mode():
    context.configure(
        url="postgresql+psycopg://",
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    database = Database(
        config.attributes.get("database_url") or os.environ["SAAS_DATABASE_URL"], for_migration=True
    )
    try:
        with database.engine.connect() as connection:
            run_online(connection)
    finally:
        database.close()
