import re
import json
from datetime import datetime, timezone, timedelta
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class CisaRssCollector(Collector):
    source_name = "cisa_rss"
    source_type = "rss"
    trust_level = 9
    supports_incremental = True

    def __init__(self, max_records: int = 200):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=10)
        self.feed_url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        try:
            resp = self.http.get(self.feed_url)
            xml_text = resp.text
        except Exception as e:
            logger.error(f"CISA RSS fetch failed: {e}")
            return advisories

        items = self._parse_rss(xml_text)
        for item in items:
            if len(advisories) >= self.max_records:
                break
            pub_date = parse_iso(item.get("pubDate"))
            if since_time and pub_date and pub_date < since_time:
                continue

            link = item.get("link", "")
            title = item.get("title", "")
            advisories.append(RawAdvisory(
                source=self.source_name,
                source_id=link,
                source_type=self.source_type,
                raw_data={
                    "title": title,
                    "link": link,
                    "description": item.get("description", ""),
                    "pubDate": item.get("pubDate", ""),
                },
            ))

        logger.info(f"CISA RSS: fetched {len(advisories)} advisories")
        return advisories

    def _parse_rss(self, xml_text: str) -> list[dict]:
        items = []
        item_blocks = re.findall(r'<item>(.*?)</item>', xml_text, re.DOTALL)
        for block in item_blocks:
            item = {}
            title_m = re.search(r'<title>(.*?)</title>', block, re.DOTALL)
            if title_m:
                item["title"] = title_m.group(1).strip()
            link_m = re.search(r'<link>(.*?)</link>', block, re.DOTALL)
            if link_m:
                item["link"] = link_m.group(1).strip()
            desc_m = re.search(r'<description>(.*?)</description>', block, re.DOTALL)
            if desc_m:
                item["description"] = desc_m.group(1).strip()
            pub_m = re.search(r'<pubDate>(.*?)</pubDate>', block, re.DOTALL)
            if pub_m:
                item["pubDate"] = pub_m.group(1).strip()
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
            except Exception:
                pub_date = None

        pk = f"cisa_rss:{link}" if link else f"cisa_rss:{title[:50]}"

        nv = NormalizedVulnerability(
            primary_key_id=pk,
            cve_id=cve_id,
            title=title,
            description=description,
            severity="HIGH",
            official_confirmed=True,
            references=[{"url": link, "source": "CISA", "tags": "advisory"}],
            published_at=pub_date,
            source=self.source_name,
            source_confidence_score=90.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )
        return [nv]
