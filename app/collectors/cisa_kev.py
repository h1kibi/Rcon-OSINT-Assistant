import json
from datetime import datetime
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class CisaKevCollector(Collector):
    source_name = "cisa_kev"
    source_type = "api"
    trust_level = 10
    supports_incremental = False

    def __init__(self, base_url: str = ""):
        self.base_url = base_url or (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        )
        self.http = HTTPClient(rate_per_minute=10)

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        try:
            data = self.http.get_json(self.base_url)
        except Exception as e:
            logger.error(f"CISA KEV fetch failed: {e}")
            raise

        vulns = data.get("vulnerabilities", [])
        advisories = []

        for item in vulns:
            cve_id = item.get("cveID", "")
            date_added = item.get("dateAdded", "")
            if since_time and date_added:
                da = parse_iso(date_added)
                if da and da < since_time:
                    continue

            advisories.append(RawAdvisory(
                source=self.source_name,
                source_id=cve_id,
                source_type=self.source_type,
                raw_data=item,
            ))

        logger.info(f"CISA KEV: fetched {len(advisories)} advisories")
        return advisories

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        cve_id = item.get("cveID", "")
        due_date_raw = item.get("dueDate")
        due_date = parse_iso(due_date_raw) if due_date_raw else None
        date_added = parse_iso(item.get("dateAdded"))

        description = (
            f"{item.get('vulnerabilityName', '')} - "
            f"{item.get('shortDescription', '')}"
        )

        nv = NormalizedVulnerability(
            primary_key_id=f"kev:{cve_id}",
            cve_id=cve_id,
            title=item.get("vulnerabilityName", cve_id),
            description=description,
            severity="HIGH",
            is_kev=True,
            kev_due_date=due_date,
            kev_known_ransomware=(
                item.get("knownRansomwareCampaignUse", "").lower() == "known"
            ),
            official_confirmed=True,
            references=[
                {
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source": "CISA KEV",
                    "tags": "kev",
                }
            ],
            affected_products=[{
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
            }],
            published_at=date_added,
            source=self.source_name,
            source_confidence_score=100.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )

        return [nv]
