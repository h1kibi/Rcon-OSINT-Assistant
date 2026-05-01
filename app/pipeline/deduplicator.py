from collections import defaultdict
from app.collectors.base import NormalizedVulnerability


def deduplicate(vulns: list[NormalizedVulnerability]) -> list[NormalizedVulnerability]:
    """Merge vulnerabilities by CVE ID, retaining highest-confidence fields."""
    groups: dict[str, list[NormalizedVulnerability]] = defaultdict(list)

    for v in vulns:
        key = v.cve_id or v.ghsa_id or v.osv_id or v.primary_key_id
        if key:
            groups[key].append(v)

    merged = []
    for key, items in groups.items():
        if len(items) == 1:
            merged.append(items[0])
            continue

        best = _merge_group(key, items)
        merged.append(best)

    return merged


def _merge_group(key: str, items: list[NormalizedVulnerability]) -> NormalizedVulnerability:
    """Merge a group of normalized vulns, preferring highest confidence source."""
    items_sorted = sorted(items, key=lambda v: v.source_confidence_score, reverse=True)
    best = items_sorted[0]

    all_sources = list({v.source for v in items})
    source_str = ",".join(all_sources)
    max_confidence = max(v.source_confidence_score for v in items)

    merged_refs = {}
    merged_products = {}
    merged_cwes = set()
    merged_cpes = set()

    for v in items:
        for ref in v.references:
            url = ref.get("url", "")
            if url and url not in merged_refs:
                merged_refs[url] = ref
        for ap in v.affected_products:
            vendor = ap.get("vendor", "")
            product = ap.get("product", "")
            combined = f"{vendor}::{product}"
            if combined not in merged_products:
                merged_products[combined] = ap
        for cwe in v.cwe_ids:
            merged_cwes.add(cwe)
        for cpe in v.cpe_list:
            merged_cpes.add(cpe)

    for v in items:
        if not best.title and v.title:
            best.title = v.title
        if not best.description and v.description:
            best.description = v.description
        if not best.severity or best.severity == "UNKNOWN":
            if v.severity and v.severity != "UNKNOWN":
                best.severity = v.severity
        if best.cvss_score is None and v.cvss_score is not None:
            best.cvss_score = v.cvss_score
        if not best.cvss_vector and v.cvss_vector:
            best.cvss_vector = v.cvss_vector
        if best.epss_score is None and v.epss_score is not None:
            best.epss_score = v.epss_score
        if best.epss_percentile is None and v.epss_percentile is not None:
            best.epss_percentile = v.epss_percentile
        if v.is_kev:
            best.is_kev = True
            if v.kev_due_date:
                best.kev_due_date = v.kev_due_date
            if v.kev_known_ransomware:
                best.kev_known_ransomware = True
        if v.official_confirmed:
            best.official_confirmed = True
        if v.has_patch:
            best.has_patch = True
        if v.has_poc_signal:
            best.has_poc_signal = True

    best.references = list(merged_refs.values())
    best.affected_products = list(merged_products.values())
    best.cwe_ids = list(merged_cwes)
    best.cpe_list = list(merged_cpes)
    best.source = source_str
    best.source_confidence_score = max_confidence

    return best
