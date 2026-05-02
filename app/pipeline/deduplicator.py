from collections import defaultdict
from datetime import datetime, timezone
from app.collectors.base import NormalizedVulnerability


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class UnionFind:
    def __init__(self):
        self._parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra


def _vuln_ids(v: NormalizedVulnerability) -> list[str]:
    """Extract all identifiers from a vulnerability for alias-graph grouping."""
    ids: list[str] = []
    for value in [v.cve_id, v.ghsa_id, v.osv_id, v.primary_key_id]:
        if value:
            ids.append(value.strip().upper())
    for alias in v.aliases:
        if alias:
            ids.append(alias.strip().upper())
    return sorted(set(ids))


def deduplicate(vulns: list[NormalizedVulnerability]) -> list[NormalizedVulnerability]:
    """Merge vulnerabilities using alias graph union-find across CVE/GHSA/OSV/aliases."""
    if not vulns:
        return []

    dsu = UnionFind()
    item_ids: list[tuple[NormalizedVulnerability, list[str]]] = []

    for v in vulns:
        ids = _vuln_ids(v)
        if not ids:
            ids = [v.primary_key_id]
        # Feed first id as canonical, link all others via union
        first = ids[0]
        for alias in ids[1:]:
            dsu.union(first, alias)
        item_ids.append((v, ids))

    # Group by canonical root
    groups: dict[str, list[NormalizedVulnerability]] = defaultdict(list)
    for v, ids in item_ids:
        root = dsu.find(ids[0])
        groups[root].append(v)

    merged = []
    for root, items in groups.items():
        if len(items) == 1:
            item = items[0]
            item.disclosed_at = item.published_at
            item.disclosed_source = item.source
            merged.append(item)
        else:
            merged.append(_merge_group(root, items))

    return merged


def _merge_group(key: str, items: list[NormalizedVulnerability]) -> NormalizedVulnerability:
    items_sorted = sorted(items, key=lambda v: v.source_confidence_score, reverse=True)
    best = items_sorted[0]

    all_sources = list(dict.fromkeys(v.source for v in items))
    source_str = ",".join(all_sources)
    max_confidence = max(v.source_confidence_score for v in items)

    merged_refs: dict[str, dict] = {}
    merged_products: dict[tuple, dict] = {}
    merged_cwes: set[str] = set()
    merged_cpes: set[str] = set()

    for v in items:
        for ref in v.references:
            url = ref.get("url", "")
            if url and url not in merged_refs:
                merged_refs[url] = ref
        for ap in v.affected_products:
            key_ap = _affected_product_key(ap)
            if key_ap not in merged_products:
                merged_products[key_ap] = ap
        for cwe in v.cwe_ids:
            merged_cwes.add(cwe)
        for cpe in v.cpe_list:
            merged_cpes.add(cpe)

    # Earliest published_at
    published_candidates = [
        (_to_utc(v.published_at), v.source)
        for v in items
        if v.published_at is not None
    ]
    if published_candidates:
        earliest_time, earliest_source = min(published_candidates, key=lambda x: x[0])
        best.disclosed_at = earliest_time
        best.disclosed_source = earliest_source
        best.published_at = earliest_time

    # Latest modified_at
    modified_dates = [_to_utc(v.modified_at) for v in items if v.modified_at]
    if modified_dates:
        best.modified_at = max(modified_dates)

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
    best.cwe_ids = sorted(merged_cwes)
    best.cpe_list = sorted(merged_cpes)
    best.source = source_str
    best.source_confidence_score = max_confidence

    return best


def _affected_product_key(product: dict) -> tuple:
    """Composite dedup key including version range and ecosystem."""
    fields = (
        "vendor",
        "product",
        "package_ecosystem",
        "package_name",
        "cpe",
        "version_start",
        "version_end",
        "fixed_version",
    )
    return tuple(str(product.get(f, "") or "").strip().lower() for f in fields)
