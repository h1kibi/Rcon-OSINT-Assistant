"""Red Hat Security Data API collector."""
import json
from datetime import datetime, timezone, timedelta
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class RedHatCollector(Collector):
    source_name = "redhat"
    source_type = "api"
    trust_level = 8
    supports_incremental = True

    def __init__(self, max_records: int = 500):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=20)
        self.base_url = "https://access.redhat.com/hydra/rest/securitydata"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        params = {"per_page": 100, "page": 0}
        if since_time:
            params["after"] = since_time.strftime("%Y-%m-%d")

        while len(advisories) < self.max_records:
            params["page"] += 1
            try:
                resp = self.http.get(f"{self.base_url}/cve.json", params=params)
                data = resp.json()
                if not data:
                    break
                for item in data:
                    cve_id = item.get("CVE", "")
                    advisories.append(RawAdvisory(
                        source=self.source_name,
                        source_id=cve_id,
                        source_type=self.source_type,
                        raw_data=item,
                    ))
            except Exception as e:
                logger.warning(f"Red Hat fetch failed: {e}")
                break

        logger.info(f"Red Hat: fetched {len(advisories)} advisories")
        return advisories[:self.max_records]

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        cve_id = item.get("CVE", "")
        title = item.get("bugzilla_description", "") or cve_id
        description = item.get("details", "") or title

        severity = (item.get("severity") or "UNKNOWN").upper()
        cvss_score = item.get("cvss3", {}).get("cvss3_base_score")
        if cvss_score:
            cvss_score = float(cvss_score)
        cvss_vector = item.get("cvss3", {}).get("cvss3_vector")

        return [NormalizedVulnerability(
            primary_key_id=f"redhat:{cve_id}",
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=[{"url": f"https://access.redhat.com/security/cve/{cve_id}", "source": "RedHat", "tags": "advisory"}],
            published_at=parse_iso(item.get("public_date")),
            source=self.source_name,
            source_confidence_score=85.0,
            official_confirmed=True,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
