"""CNVD (China National Vulnerability Database) collector - RSS/HTML parsing."""
import json
import re
from datetime import datetime, timezone
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class CNVDCollector(Collector):
    source_name = "cnvd"
    source_type = "web"
    trust_level = 7
    supports_incremental = False

    def __init__(self, max_records: int = 200):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=5, timeout=15.0)
        self.base_url = "https://www.cnvd.org.cn"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        try:
            # CNVD doesn't have a stable public API, parse RSS or web
            resp = self.http.get(f"{self.base_url}/flaw/list")
            items = self._parse_html(resp.text)
            for item in items[:self.max_records]:
                advisories.append(RawAdvisory(
                    source=self.source_name,
                    source_id=item.get("cnvd_id", ""),
                    source_type=self.source_type,
                    raw_data=item,
                ))
        except Exception as e:
            logger.warning(f"CNVD fetch failed (may be blocked): {e}")

        logger.info(f"CNVD: fetched {len(advisories)} advisories")
        return advisories

    def _parse_html(self, html: str) -> list[dict]:
        """Parse CNVD HTML table for vulnerability list."""
        items = []
        # Try to extract table rows
        rows = re.findall(r'<tr>(.*?)</tr>', html, re.DOTALL)
        for row in rows:
            cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
            if len(cells) >= 3:
                cnvd_id = re.sub(r'<[^>]+>', '', cells[0]).strip()
                title = re.sub(r'<[^>]+>', '', cells[1]).strip()
                if cnvd_id.startswith("CNVD-"):
                    items.append({
                        "cnvd_id": cnvd_id,
                        "title": title,
                        "severity": re.sub(r'<[^>]+>', '', cells[2]).strip() if len(cells) > 2 else "",
                    })
        return items

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        cnvd_id = item.get("cnvd_id", "")
        title = item.get("title", cnvd_id)
        severity = (item.get("severity") or "UNKNOWN").upper()

        cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', title)
        cve_id = cve_ids[0] if cve_ids else None

        return [NormalizedVulnerability(
            primary_key_id=f"cnvd:{cnvd_id}",
            cve_id=cve_id,
            title=title,
            description=item.get("description", ""),
            severity=severity,
            references=[{"url": f"https://www.cnvd.org.cn/flaw/show/{cnvd_id}", "source": "CNVD", "tags": "advisory"}],
            source=self.source_name,
            source_confidence_score=70.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
