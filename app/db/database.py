from sqlmodel import SQLModel, Session, create_engine
from loguru import logger
import re

engine = None


def _redact_url(url: str) -> str:
    return re.sub(r'://[^@]*@', '://***:***@', url)


def init_db(database_url: str):
    """Initialize SQLite database and create all tables."""
    global engine
    engine = create_engine(
        database_url,
        echo=False,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,
        },
    )
    SQLModel.metadata.create_all(engine)
    logger.info(f"Database initialized: {_redact_url(database_url)}")


def get_session() -> Session:
    """Get a new database session."""
    return Session(engine)
