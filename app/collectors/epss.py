from datetime import datetime
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient


class EPSSCollector(Collector):
    source_name = "epss"
    source_type = "api"
    trust_level = 8
    supports_incremental = True

    def __init__(self, base_url: str = ""):
        self.base_url = base_url or "https://api.first.org/data/v1/epss"
        self.http = HTTPClient(rate_per_minute=30)

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        return []

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        return []

    def enrich(self, cve_ids: list[str]) -> dict[str, dict]:
        """Batch query EPSS scores for a list of CVEs."""
        if not cve_ids:
            return {}

        results = {}
        batch_size = 100

        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            cve_param = ",".join(batch)
            try:
                resp = self.http.get(
                    self.base_url,
                    params={"cve": cve_param},
                )
                data = resp.json()
            except Exception as e:
                logger.error(f"EPSS batch query failed: {e}")
                continue

            for entry in data.get("data", []):
                cve = entry.get("cve", "")
                epss = entry.get("epss")
                percentile = entry.get("percentile")
                try:
                    results[cve] = {
                        "epss_score": float(epss) if epss else None,
                        "epss_percentile": float(percentile) if percentile else None,
                    }
                except (ValueError, TypeError):
                    pass

        logger.info(f"EPSS: enriched {len(results)} CVEs")
        return results
