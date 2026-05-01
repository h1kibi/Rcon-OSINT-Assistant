"""Chinese security vendor advisory collector (RSS aggregation).
Covers: QiAnXin CERT, NSFOCUS, Sangfor, Alibaba Cloud, Tencent, Huawei."""
import json
import re
from datetime import datetime, timezone
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class ChineseVendorCollector(Collector):
    """Aggregator for Chinese security vendor RSS feeds."""
    source_name = "cn_vendor"
    source_type = "rss"
    trust_level = 7
    supports_incremental = True

    RSS_FEEDS = {
        "qianxin": "https://cert.qianxin.com/rss",
        "nsfocus": "https://www.nsfocus.net/rss",
        "sangfor": "https://sec.sangfor.com.cn/rss",
    }

    def __init__(self, max_records: int = 200):
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=10, timeout=15.0)

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        for vendor, url in self.RSS_FEEDS.items():
            if len(advisories) >= self.max_records:
                break
            try:
                resp = self.http.get(url)
                items = self._parse_rss(resp.text, vendor)
                for item in items:
                    if len(advisories) >= self.max_records:
                        break
                    advisories.append(RawAdvisory(
                        source=f"cn_{vendor}",
                        source_id=item.get("link", ""),
                        source_type=self.source_type,
                        raw_data=item,
                    ))
            except Exception as e:
                logger.warning(f"Chinese vendor {vendor} fetch failed: {e}")

        logger.info(f"Chinese vendors: fetched {len(advisories)} advisories")
        return advisories

    def _parse_rss(self, xml_text: str, vendor: str) -> list[dict]:
        items = []
        blocks = re.findall(r'<item>(.*?)</item>', xml_text, re.DOTALL)
        for block in blocks:
            item = {"vendor": vendor}
            for tag in ["title", "link", "description", "pubDate"]:
                m = re.search(f'<{tag}>(.*?)</{tag}>', block, re.DOTALL)
                if m:
                    item[tag] = m.group(1).strip()
            items.append(item)
        return items

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        vendor = item.get("vendor", "")
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
            primary_key_id=f"cn_{vendor}:{link}",
            cve_id=cve_id,
            title=title,
            description=description,
            severity="UNKNOWN",
            references=[{"url": link, "source": vendor, "tags": "advisory"}],
            published_at=pub_date,
            source=f"cn_{vendor}",
            source_confidence_score=65.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
