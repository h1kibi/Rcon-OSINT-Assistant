import sys
from loguru import logger


def setup_logging(level: str = "INFO", log_format: str = None,
                  rotation: str = "10 MB", retention: str = "7 days"):
    """Configure loguru logging."""
    logger.remove()

    if log_format is None:
        log_format = (
            "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | "
            "{name}:{function}:{line} | {message}"
        )

    logger.add(
        sys.stderr,
        level=level,
        format=log_format,
        colorize=True,
    )

    logger.add(
        "logs/rcon_{time:YYYY-MM-DD}.log",
        level=level,
        format=log_format,
        rotation=rotation,
        retention=retention,
        encoding="utf-8",
    )

    return logger
