"""Debian Security Tracker collector."""
import json
from datetime import datetime, timezone, timedelta
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class DebianCollector(Collector):
    source_name = "debian"
    source_type = "api"
    trust_level = 7
    supports_incremental = True

    def __init__(self, max_records: int = 500):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=20)
        self.base_url = "https://security-tracker.debian.org/tracker/api"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        try:
            resp = self.http.get(f"{self.base_url}/json")
            data = resp.json()
            for cve_id, cve_data in list(data.items())[:self.max_records]:
                if cve_id.startswith("CVE-"):
                    advisories.append(RawAdvisory(
                        source=self.source_name,
                        source_id=cve_id,
                        source_type=self.source_type,
                        raw_data={"cve_id": cve_id, **cve_data},
                    ))
        except Exception as e:
            logger.warning(f"Debian fetch failed: {e}")

        logger.info(f"Debian: fetched {len(advisories)} advisories")
        return advisories[:self.max_records]

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        cve_id = item.get("cve_id", "")
        description = item.get("description", "")

        severity = "UNKNOWN"
        urgency = item.get("urgency", "")
        if urgency in ["high", "critical"]:
            severity = "HIGH"
        elif urgency == "medium":
            severity = "MEDIUM"
        elif urgency == "low":
            severity = "LOW"

        return [NormalizedVulnerability(
            primary_key_id=f"debian:{cve_id}",
            cve_id=cve_id,
            title=f"{cve_id} - Debian Security Tracker",
            description=description,
            severity=severity,
            references=[{"url": f"https://security-tracker.debian.org/tracker/{cve_id}", "source": "Debian", "tags": "advisory"}],
            source=self.source_name,
            source_confidence_score=75.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
