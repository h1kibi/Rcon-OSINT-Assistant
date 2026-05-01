"""Microsoft MSRC Security Update Guide collector."""
import json
from datetime import datetime, timezone, timedelta
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class MSRCCollector(Collector):
    source_name = "msrc"
    source_type = "api"
    trust_level = 9
    supports_incremental = True

    def __init__(self, api_key: str = "", max_records: int = 500):
        self.max_records = max_records
        headers = {"Accept": "application/json"}
        if api_key:
            headers["api-key"] = api_key
        self.http = HTTPClient(rate_per_minute=10, headers=headers)
        self.base_url = "https://api.msrc.microsoft.com/cvrf/v3.0"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        try:
            # Get recent updates
            resp = self.http.get(f"{self.base_url}/updates")
            data = resp.json()
            updates = data.get("value", [])[:20]  # Last 20 updates

            for update in updates:
                if len(advisories) >= self.max_records:
                    break
                update_id = update.get("ID", "")
                try:
                    detail_resp = self.http.get(f"{self.base_url}/updates/{update_id}")
                    detail = detail_resp.json()
                    for vuln in detail.get("vulnerabilities", []):
                        cve_id = vuln.get("cveNumber", "")
                        if cve_id:
                            advisories.append(RawAdvisory(
                                source=self.source_name,
                                source_id=cve_id,
                                source_type=self.source_type,
                                raw_data={**vuln, "update_id": update_id},
                            ))
                except Exception as e:
                    logger.debug(f"MSRC update {update_id} failed: {e}")
        except Exception as e:
            logger.error(f"MSRC fetch failed: {e}")

        logger.info(f"MSRC: fetched {len(advisories)} advisories")
        return advisories[:self.max_records]

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        cve_id = item.get("cveNumber", "")
        title = item.get("title", {}).get("value", "") if isinstance(item.get("title"), dict) else str(item.get("title", ""))
        description = item.get("description", {}).get("value", "") if isinstance(item.get("description"), dict) else ""

        # CVSS from metrics
        cvss_score = None
        for metric in item.get("metrics", []):
            score = metric.get("cvssV3_1", {}).get("baseScore")
            if score:
                cvss_score = float(score)
                break

        severity = "UNKNOWN"
        for s in item.get("severity", []):
            if isinstance(s, dict):
                severity = s.get("value", "UNKNOWN").upper()
                break

        return [NormalizedVulnerability(
            primary_key_id=f"msrc:{cve_id}",
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            references=[{"url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}", "source": "MSRC", "tags": "advisory"}],
            source=self.source_name,
            source_confidence_score=90.0,
            official_confirmed=True,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
