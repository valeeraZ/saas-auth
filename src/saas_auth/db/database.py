import psycopg
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class Database:
    def __init__(self, dsn: str, *, for_migration: bool = False) -> None:
        # libpq accepts both URLs and keyword DSNs (including Unix sockets).
        # Data migrations can legitimately run longer than the API statement deadline.
        options = None if for_migration else "-c statement_timeout=5000 -c lock_timeout=3000"
        self.engine = create_engine(
            "postgresql+psycopg://",
            creator=lambda: psycopg.connect(dsn, connect_timeout=5, options=options),
            pool_size=8,
            max_overflow=0,
            pool_timeout=5,
            pool_pre_ping=True,
            hide_parameters=True,
        )
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def close(self) -> None:
        self.engine.dispose()
