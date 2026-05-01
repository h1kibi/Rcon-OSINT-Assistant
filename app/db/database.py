from sqlmodel import SQLModel, Session, create_engine
from loguru import logger

engine = None


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
    logger.info(f"Database initialized: {database_url}")


def get_session() -> Session:
    """Get a new database session."""
    return Session(engine)
