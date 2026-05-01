"""CNNVD (China National Vulnerability Database of Information Security) collector."""
import json
import re
from datetime import datetime, timezone
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class CNNVDCollector(Collector):
    source_name = "cnnvd"
    source_type = "web"
    trust_level = 7
    supports_incremental = False

    def __init__(self, max_records: int = 200):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=5, timeout=15.0)
        self.base_url = "https://www.cnnvd.org.cn"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        try:
            resp = self.http.get(f"{self.base_url}/web/vulnerability/querylist")
            items = self._parse_html(resp.text)
            for item in items[:self.max_records]:
                advisories.append(RawAdvisory(
                    source=self.source_name,
                    source_id=item.get("cnnvd_id", ""),
                    source_type=self.source_type,
                    raw_data=item,
                ))
        except Exception as e:
            logger.warning(f"CNNVD fetch failed (may be blocked): {e}")

        logger.info(f"CNNVD: fetched {len(advisories)} advisories")
        return advisories

    def _parse_html(self, html: str) -> list[dict]:
        items = []
        rows = re.findall(r'<tr>(.*?)</tr>', html, re.DOTALL)
        for row in rows:
            cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
            if len(cells) >= 3:
                cnnvd_id = re.sub(r'<[^>]+>', '', cells[0]).strip()
                cve_id = re.sub(r'<[^>]+>', '', cells[1]).strip()
                title = re.sub(r'<[^>]+>', '', cells[2]).strip()
                if cnnvd_id.startswith("CNNVD-"):
                    items.append({
                        "cnnvd_id": cnnvd_id,
                        "cve_id": cve_id if cve_id.startswith("CVE-") else None,
                        "title": title,
                    })
        return items

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        cnnvd_id = item.get("cnnvd_id", "")
        cve_id = item.get("cve_id")
        title = item.get("title", cnnvd_id)

        return [NormalizedVulnerability(
            primary_key_id=f"cnnvd:{cnnvd_id}",
            cve_id=cve_id,
            title=title,
            description=item.get("description", ""),
            severity="UNKNOWN",
            references=[{"url": f"https://www.cnnvd.org.cn/web/vulnerability/querylist?cnnvdId={cnnvd_id}", "source": "CNNVD", "tags": "advisory"}],
            source=self.source_name,
            source_confidence_score=70.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
