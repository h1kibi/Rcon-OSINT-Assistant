"""Ubuntu Security Notices collector."""
import json
import re
from datetime import datetime, timezone
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class UbuntuCollector(Collector):
    source_name = "ubuntu"
    source_type = "rss"
    trust_level = 8
    supports_incremental = True

    def __init__(self, max_records: int = 200):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=10)
        self.rss_url = "https://ubuntu.com/security/notices/rss.xml"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        try:
            resp = self.http.get(self.rss_url)
            items = self._parse_rss(resp.text)
            for item in items[:self.max_records]:
                advisories.append(RawAdvisory(
                    source=self.source_name,
                    source_id=item.get("link", ""),
                    source_type=self.source_type,
                    raw_data=item,
                ))
        except Exception as e:
            logger.error(f"Ubuntu RSS fetch failed: {e}")

        logger.info(f"Ubuntu: fetched {len(advisories)} advisories")
        return advisories

    def _parse_rss(self, xml_text: str) -> list[dict]:
        items = []
        blocks = re.findall(r'<item>(.*?)</item>', xml_text, re.DOTALL)
        for block in blocks:
            item = {}
            for tag in ["title", "link", "description", "pubDate"]:
                m = re.search(f'<{tag}>(.*?)</{tag}>', block, re.DOTALL)
                if m:
                    item[tag] = m.group(1).strip()
            items.append(item)
        return items

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        title = item.get("title", "")
        link = item.get("link", "")
        description = item.get("description", "")

        cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', f"{title} {description}")
        cve_id = cve_ids[0] if cve_ids else None

        pub_date = None
        pub_str = item.get("pubDate", "")
        if pub_str:
            try:
                from email.utils import parsedate_to_datetime
                pub_date = parsedate_to_datetime(pub_str)
            except:
                pass

        return [NormalizedVulnerability(
            primary_key_id=f"ubuntu:{link}",
            cve_id=cve_id,
            title=title,
            description=description,
            severity="HIGH",
            official_confirmed=True,
            references=[{"url": link, "source": "Ubuntu", "tags": "advisory"}],
            published_at=pub_date,
            source=self.source_name,
            source_confidence_score=80.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
