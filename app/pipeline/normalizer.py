from datetime import datetime, timezone
from loguru import logger
from app.collectors.base import NormalizedVulnerability, RawAdvisory


def _normalize_dt(dt: datetime | None) -> datetime | None:
    """Ensure all datetimes are UTC-aware before entering the pipeline."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize(raws: list[RawAdvisory], collectors: dict) -> list[NormalizedVulnerability]:
    """Run normalization on raw advisories using their collector."""
    result = []
    for raw in raws:
        collector = collectors.get(raw.source)
        if collector:
            try:
                normalized_list = collector.normalize(raw)
                result.extend(normalized_list)
            except Exception as e:
                logger.warning(
                    f"Failed to normalize {raw.source_id} from {raw.source}: {e}"
                )
                continue

    # Ensure all datetime fields are UTC-aware before pipeline processing
    for item in result:
        item.published_at = _normalize_dt(item.published_at)
        item.modified_at = _normalize_dt(item.modified_at)
        item.disclosed_at = _normalize_dt(item.disclosed_at)

    return result
