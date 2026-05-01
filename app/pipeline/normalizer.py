from loguru import logger
from app.collectors.base import NormalizedVulnerability, RawAdvisory


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
    return result
