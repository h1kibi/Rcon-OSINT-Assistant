import json
from datetime import datetime, timezone, timedelta
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class OSVCollector(Collector):
    source_name = "osv"
    source_type = "api"
    trust_level = 7
    supports_incremental = True

    ECOSYSTEMS = [
        "npm", "PyPI", "Go", "Maven", "crates.io", "NuGet",
        "Packagist", "RubyGems", "Hex", "Pub",
    ]

    def __init__(self, base_url: str = "", max_records: int = 500):
        self.base_url = base_url or "https://api.osv.dev/v1"
        self.max_records = max_records
        self.http = HTTPClient(rate_per_minute=20, timeout=15.0, max_retries=2)

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        if since_time is None:
            since_time = datetime.now(timezone.utc) - timedelta(days=3)

        for eco in self.ECOSYSTEMS:
            if len(advisories) >= self.max_records:
                break
            try:
                batch = self._fetch_ecosystem(eco, since_time)
                advisories.extend(batch)
            except Exception as e:
                logger.warning(f"OSV fetch failed for {eco}: {e}")

        logger.info(f"OSV: fetched {len(advisories)} advisories")
        return advisories[:self.max_records]

    def _fetch_ecosystem(self, ecosystem: str, since: datetime) -> list[RawAdvisory]:
        url = f"{self.base_url}/query"
        results = []
        page_token = None
        max_per_eco = self.max_records // len(self.ECOSYSTEMS)

        while len(results) < max_per_eco:
            body = {"page_size": 100, "ecosystem": ecosystem}
            if page_token:
                body["page_token"] = page_token

            try:
                resp = self.http.post(url, json=body)
                data = resp.json()
            except Exception as e:
                logger.debug(f"OSV {ecosystem} query failed: {e}")
                break

            vulns = data.get("vulns", [])
            if not vulns:
                break

            for item in vulns:
                osv_id = item.get("id", "")
                modified = parse_iso(item.get("modified"))
                if modified and modified < since:
                    continue
                results.append(RawAdvisory(
                    source=self.source_name,
                    source_id=osv_id,
                    source_type=self.source_type,
                    raw_data=item,
                ))

            page_token = data.get("next_page_token")
            if not page_token:
                break

        return results

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        osv_id = item.get("id", "")

        cve_id = None
        aliases = item.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        summary = item.get("summary", "") or ""
        details = item.get("details", "") or ""
        title = summary or details[:120]

        severity = "UNKNOWN"
        cvss_score = None
        cvss_vector = None
        for sev in item.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                cvss_vector = sev.get("score", "")
                break

        affected_products = []
        for aff in item.get("affected", []):
            pkg = aff.get("package", {})
            eco = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            for rng in aff.get("ranges", []):
                events = rng.get("events", [])
                introduced = None
                fixed = None
                for ev in events:
                    if "introduced" in ev:
                        introduced = ev["introduced"]
                    if "fixed" in ev:
                        fixed = ev["fixed"]
                affected_products.append({
                    "vendor": eco, "product": name,
                    "package_name": name, "package_ecosystem": eco,
                    "version_start": introduced or "",
                    "fixed_version": fixed or "",
                })

        references = []
        for ref in item.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": "OSV",
                "tags": ref.get("type", ""),
            })

        published = parse_iso(item.get("published"))
        modified = parse_iso(item.get("modified"))

        pk = f"osv:{cve_id}" if cve_id else f"osv:{osv_id}"

        return [NormalizedVulnerability(
            primary_key_id=pk,
            cve_id=cve_id,
            osv_id=osv_id,
            title=title,
            description=details,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_products=affected_products,
            references=references,
            published_at=published,
            modified_at=modified,
            source=self.source_name,
            source_confidence_score=75.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )]
