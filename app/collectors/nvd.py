import json
from datetime import datetime, timedelta, timezone
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class NVDCollector(Collector):
    source_name = "nvd"
    source_type = "api"
    trust_level = 9
    supports_incremental = True

    def __init__(self, api_key: str = "", base_url: str = "",
                 rate_limit_per_minute: int = 20, initial_sync_days: int = 3,
                 max_records: int = 1000):
        self.api_key = api_key
        self.base_url = base_url or "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.initial_sync_days = initial_sync_days
        self.max_records = max_records
        headers = {}
        if api_key:
            headers["apiKey"] = api_key
        self.http = HTTPClient(rate_per_minute=rate_limit_per_minute, headers=headers)
        self._cursor = None

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        if since_time is None:
            since_time = datetime.now(timezone.utc) - timedelta(days=self.initial_sync_days)

        start_str = since_time.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

        advisories = []
        start_index = 0
        page_size = 100

        while len(advisories) < self.max_records:
            params = {
                "pubStartDate": start_str,
                "pubEndDate": end_str,
                "startIndex": start_index,
                "resultsPerPage": min(page_size, self.max_records - len(advisories)),
            }
            try:
                data = self.http.get_json(self.base_url, params=params)
            except Exception as e:
                logger.error(f"NVD fetch failed: {e}")
                raise

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                advisories.append(RawAdvisory(
                    source=self.source_name,
                    source_id=cve_id,
                    source_type=self.source_type,
                    raw_data=item,
                ))

            total_results = data.get("totalResults", 0)
            start_index += page_size
            logger.debug(
                f"NVD: fetched {len(advisories)}/{min(total_results, self.max_records)} "
                f"(page {start_index // page_size})"
            )
            if start_index >= total_results:
                break

        logger.info(f"NVD: fetched {len(advisories)} advisories (limit: {self.max_records})")
        return advisories

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        cve_data = raw.raw_data.get("cve", {})
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        title = ""
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                title = description[:120] if description else ""
                break

        # CVSS
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        severity = "UNKNOWN"
        cvss_v31 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_v31:
            cvss = cvss_v31[0].get("cvssData", {})
            cvss_score = cvss.get("baseScore")
            cvss_vector = cvss.get("vectorString")
            severity = cvss_v31[0].get("baseSeverity", "UNKNOWN")

        # References
        refs_raw = cve_data.get("references", [])
        references = []
        for r in refs_raw:
            tags_list = r.get("tags", [])
            if isinstance(tags_list, list):
                tags = ",".join(
                    t if isinstance(t, str) else str(t) for t in tags_list
                )
            else:
                tags = str(tags_list)
            references.append({
                "url": r.get("url", ""),
                "source": r.get("source", ""),
                "tags": tags,
            })

        # CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                cwe_ids.append(desc.get("value", ""))

        # CPE
        cpe_list = []
        configurations = cve_data.get("configurations", [])
        for conf in configurations:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_list.append(match.get("criteria", ""))

        # Dates
        published = cve_data.get("published")
        modified = cve_data.get("lastModified")
        pub_date = parse_iso(published)
        mod_date = parse_iso(modified)

        nv = NormalizedVulnerability(
            primary_key_id=f"nvd:{cve_id}",
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            cpe_list=cpe_list,
            references=references,
            published_at=pub_date,
            modified_at=mod_date,
            source=self.source_name,
            source_confidence_score=85.0,
            raw_json=json.dumps(cve_data, ensure_ascii=False, default=str),
        )

        return [nv]
