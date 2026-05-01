import json
from datetime import datetime, timezone
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient
from app.utils.time import parse_iso


class GitHubAdvisoryCollector(Collector):
    source_name = "github_advisory"
    source_type = "api"
    trust_level = 8
    supports_incremental = True

    def __init__(self, token: str = "", max_records: int = 1000):
        self.max_records = max_records
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.http = HTTPClient(rate_per_minute=30, headers=headers)
        self.base_url = "https://api.github.com/advisories"

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        advisories = []
        page = 1
        per_page = 100

        if since_time:
            logger.debug(f"GitHub Advisory: since_time={since_time}")

        while len(advisories) < self.max_records:
            params = {
                "type": "reviewed",
                "sort": "published",
                "direction": "desc",
                "per_page": per_page,
                "page": page,
            }
            # Only filter by date on first page to avoid missing updates
            if since_time and page == 1:
                params["published"] = f">={since_time.strftime('%Y-%m-%d')}"
                logger.debug(f"GitHub Advisory: published filter={params['published']}")

            try:
                data = self.http.get_json(self.base_url, params=params)
                logger.debug(f"GitHub Advisory: page {page}, got {len(data) if isinstance(data, list) else 'error'} items")
            except Exception as e:
                logger.error(f"GitHub Advisory fetch failed: {e}")
                break

            if not data or not isinstance(data, list):
                break

            for item in data:
                ghsa_id = item.get("ghsa_id", "")
                advisories.append(RawAdvisory(
                    source=self.source_name,
                    source_id=ghsa_id,
                    source_type=self.source_type,
                    raw_data=item,
                ))

            if len(data) < per_page:
                break
            page += 1
            logger.debug(f"GitHub Advisory: fetched {len(advisories)} (page {page})")

        logger.info(f"GitHub Advisory: fetched {len(advisories)} advisories")
        return advisories

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        item = raw.raw_data
        ghsa_id = item.get("ghsa_id", "")
        cve_id = None
        cve_ids = item.get("cve_ids", [])
        if cve_ids:
            cve_id = cve_ids[0]

        severity = (item.get("severity") or "unknown").upper()
        cvss_score = None
        cvss_vector = None
        cvss = item.get("cvss", {})
        if cvss:
            cvss_score = cvss.get("score")
            cvss_vector = cvss.get("vector_string")

        description = item.get("description", "") or ""
        summary = item.get("summary", "") or ""
        title = summary or description[:120]

        # Affected packages
        affected_products = []
        for vuln in item.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            affected_products.append({
                "vendor": pkg.get("ecosystem", ""),
                "product": pkg.get("name", ""),
                "package_name": pkg.get("name", ""),
                "package_ecosystem": pkg.get("ecosystem", ""),
                "version_start": vuln.get("vulnerable_version_range", ""),
                "fixed_version": vuln.get("first_patched_version", ""),
            })

        # References
        references = []
        references.append({
            "url": item.get("html_url", ""),
            "source": "GitHub Advisory",
            "tags": "advisory",
        })
        for ref in item.get("references", []):
            if isinstance(ref, dict):
                url = ref.get("url", "")
            else:
                url = str(ref)
            if url:
                references.append({"url": url, "source": "GitHub", "tags": "reference"})

        published = parse_iso(item.get("published_at"))
        modified = parse_iso(item.get("updated_at"))

        # Check for patch
        has_patch = any(
            vuln.get("first_patched_version")
            for vuln in item.get("vulnerabilities", [])
        )

        pk = f"ghsa:{ghsa_id}"
        if cve_id:
            pk = f"github:{cve_id}"

        nv = NormalizedVulnerability(
            primary_key_id=pk,
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_products=affected_products,
            references=references,
            has_patch=has_patch,
            official_confirmed=True,
            published_at=published,
            modified_at=modified,
            source=self.source_name,
            source_confidence_score=80.0,
            raw_json=json.dumps(item, ensure_ascii=False, default=str),
        )
        return [nv]
