"""Cisco PSIRT openVuln collector."""
import json
import time
from datetime import datetime, timezone
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class CiscoCollector(Collector):
    source_name = "cisco"
    source_type = "api"
    trust_level = 9
    supports_incremental = True

    def __init__(self, client_id: str = "", client_secret: str = "", max_records: int = 300):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=10)
        self.base_url = "https://apix.cisco.com/security/advisories/v2/all"
        self.token = None
        self.token_expires_at = 0
        self.client_id = client_id
        self.client_secret = client_secret

    def _get_token(self):
        if self.token and time.time() < self.token_expires_at:
            return self.token
        try:
            resp = self.http.post(
                "https://cloudsso.cisco.com/as/token.oauth2",
                data={"grant_type": "client_credentials"},
                auth=(self.client_id, self.client_secret),
            )
            payload = resp.json()
            self.token = payload.get("access_token")
            expires_in = int(payload.get("expires_in", 3600))
            self.token_expires_at = time.time() + expires_in - 60
            return self.token
        except Exception as e:
            logger.warning(f"Cisco token failed: {e}")
            return None

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        try:
            headers = {"Accept": "application/json"}
            if self.client_id and self.client_secret:
                token = self._get_token()
                if token:
                    headers["Authorization"] = f"Bearer {token}"

            resp = self.http.get(self.base_url, headers=headers)
            data = resp.json()

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("advisories") or data.get("advisory") or data.get("data") or []
            else:
                items = []

            for item in items[:self.max_records]:
                advisories.append(RawAdvisory(
                    source=self.source_name,
                    source_id=item.get("advisoryId", ""),
                    source_type=self.source_type,
                    raw_data=item,
                ))
        except Exception as e:
            logger.warning(f"Cisco fetch failed: {e}")

        logger.info(f"Cisco: fetched {len(advisories)} advisories")
        return advisories

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        cve_id = item.get("cve", "")
        title = item.get("title", "")
        description = item.get("summary", "")

        severity = item.get("sir", "UNKNOWN").upper()
        cvss_score = None
        cvss_vector = item.get("cvss", {}).get("cvssV3_1", {}).get("vectorString")
        cvss_score = item.get("cvss", {}).get("cvssV3_1", {}).get("baseScore")
        if cvss_score:
            cvss_score = float(cvss_score)

        return [NormalizedVulnerability(
            primary_key_id=f"cisco:{cve_id or raw.source_id}",
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=[{"url": item.get("url", ""), "source": "Cisco", "tags": "advisory"}],
            published_at=parse_iso(item.get("firstPublished")),
            modified_at=parse_iso(item.get("lastUpdated")),
            source=self.source_name,
            source_confidence_score=90.0,
            official_confirmed=True,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
