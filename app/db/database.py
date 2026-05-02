from pathlib import Path
from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy import event
from loguru import logger
from app.utils.http import redact_url

engine = None


def ensure_sqlite_parent_dir(database_url: str):
    """Create parent directory for SQLite database file if needed."""
    url = make_url(database_url)
    if url.drivername.startswith("sqlite") and url.database and url.database != ":memory:":
        Path(url.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def _set_sqlite_pragmas(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def init_db(database_url: str):
    """Initialize SQLite database and create all tables."""
    global engine
    ensure_sqlite_parent_dir(database_url)
    engine = create_engine(
        database_url,
        echo=False,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,
        },
    )
    event.listen(engine, "connect", _set_sqlite_pragmas)
    SQLModel.metadata.create_all(engine)
    logger.info(f"Database initialized: {redact_url(database_url)}")


def get_session() -> Session:
    """Get a new database session."""
    return Session(engine)
