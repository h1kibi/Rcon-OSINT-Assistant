import json
from dataclasses import dataclass
from datetime import datetime, timezone
from loguru import logger


@dataclass
class ScorerConfig:
    kev_weight: int = 35
    epss_95_weight: int = 20
    epss_85_weight: int = 12
    cvss_critical_weight: int = 20
    cvss_high_weight: int = 12
    recent_24h_weight: int = 12
    recent_7d_weight: int = 8
    official_confirmed_weight: int = 10
    patch_available_weight: int = 8
    poc_signal_weight: int = 10
    multi_source_confirmed_weight: int = 8
    watch_keyword_weight: int = 15
    watch_keywords: list[str] | None = None
    watch_vendors: list[str] | None = None
    watch_products: list[str] | None = None


HIGH_RISK_KEYWORDS = [
    "RCE", "远程代码执行", "remote code execution",
    "auth bypass", "authentication bypass", "权限提升",
    "privilege escalation", "命令执行", "command execution",
    "反序列化", "deserialization", "SQL injection", "SQL注入",
    "0day", "zero-day", "sandbox escape", "沙箱逃逸",
    "buffer overflow", "缓冲区溢出", "use after free",
    "arbitrary code", "任意代码",
]


def calculate_score(vuln: dict, config: ScorerConfig) -> tuple[float, list[str]]:
    """
    Calculate action_value_score (0-100) for a vulnerability.
    Returns (score, reasons).
    """
    score = 0.0
    reasons = []

    watch_keywords = config.watch_keywords or []
    watch_vendors = config.watch_vendors or []
    watch_products = config.watch_products or []

    # CISA KEV hit
    if vuln.get("is_kev"):
        score += config.kev_weight
        reasons.append(f"KEV命中: +{config.kev_weight}")

    # EPSS
    epss_pct = vuln.get("epss_percentile")
    epss_pct = epss_pct if epss_pct is not None else 0
    if epss_pct >= 0.95:
        score += config.epss_95_weight
        reasons.append(f"EPSS分位 {epss_pct:.2f} >= 0.95: +{config.epss_95_weight}")
    elif epss_pct >= 0.85:
        score += config.epss_85_weight
        reasons.append(f"EPSS分位 {epss_pct:.2f} >= 0.85: +{config.epss_85_weight}")

    # CVSS
    cvss = vuln.get("cvss_score")
    cvss = cvss if cvss is not None else 0
    if cvss >= 9.0:
        score += config.cvss_critical_weight
        reasons.append(f"CVSS {cvss} >= 9.0: +{config.cvss_critical_weight}")
    elif cvss >= 7.0:
        score += config.cvss_high_weight
        reasons.append(f"CVSS {cvss} >= 7.0: +{config.cvss_high_weight}")

    # Recency
    published = vuln.get("published_at")
    if published:
        if isinstance(published, str):
            from app.utils.time import parse_iso
            published = parse_iso(published)
        if published and published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        if published:
            hours_ago = (datetime.now(timezone.utc) - published).total_seconds() / 3600
            if hours_ago <= 24:
                score += config.recent_24h_weight
                reasons.append(f"24h内发布: +{config.recent_24h_weight}")
            elif hours_ago <= 168:
                score += config.recent_7d_weight
                reasons.append(f"7天内发布: +{config.recent_7d_weight}")

    # Official confirmation
    if vuln.get("official_confirmed"):
        score += config.official_confirmed_weight
        reasons.append(f"官方确认: +{config.official_confirmed_weight}")

    # Has patch
    if vuln.get("has_patch"):
        score += config.patch_available_weight
        reasons.append(f"官方补丁可用: +{config.patch_available_weight}")

    # Has PoC signal
    if vuln.get("has_poc_signal"):
        score += config.poc_signal_weight
        reasons.append(f"公开PoC信号: +{config.poc_signal_weight}")

    # Multi-source confirmation
    source_field = vuln.get("source", "")
    source_count = len([s for s in source_field.split(",") if s.strip()])
    if source_count >= 2:
        score += config.multi_source_confirmed_weight
        reasons.append(f"多源确认({source_count}源): +{config.multi_source_confirmed_weight}")

    # Watch keywords in title/description
    title = vuln.get("title", "") or ""
    description = vuln.get("description", "") or ""
    combined = f"{title} {description}".lower()
    matched_keywords = [kw for kw in watch_keywords if kw.lower() in combined]
    if matched_keywords:
        score += config.watch_keyword_weight
        reasons.append(f"命中关注关键词({','.join(matched_keywords)}): +{config.watch_keyword_weight}")

    # High-risk keywords in description
    high_risk_matches = [kw for kw in HIGH_RISK_KEYWORDS if kw.lower() in combined]
    if high_risk_matches and not matched_keywords:
        bonus = min(len(high_risk_matches) * 3, 10)
        score += bonus
        reasons.append(f"高危关键词({','.join(high_risk_matches[:3])}): +{bonus}")

    # Watch vendors/products
    affected_products = vuln.get("affected_products", [])
    if isinstance(affected_products, str):
        try:
            affected_products = json.loads(affected_products)
        except (json.JSONDecodeError, TypeError):
            affected_products = []
    if not isinstance(affected_products, list):
        affected_products = []
    matched_vendor = False
    matched_product = False
    for ap in affected_products:
        if isinstance(ap, dict):
            vendor = (ap.get("vendor") or "").lower()
            product_name = (ap.get("product") or ap.get("package_name") or "").lower()
            if not matched_vendor and watch_vendors and any(v.lower() in vendor for v in watch_vendors):
                matched_vendor = True
            if not matched_product and watch_products and any(p.lower() in product_name for p in watch_products):
                matched_product = True
    if matched_vendor:
        score += config.watch_keyword_weight
        reasons.append(f"命中关注厂商: +{config.watch_keyword_weight}")
    if matched_product:
        score += config.watch_keyword_weight
        reasons.append(f"命中关注产品: +{config.watch_keyword_weight}")

    # Penalty for low-confidence-only sources
    if vuln.get("source_confidence_score", 0) <= 40:
        penalty = 15
        score -= penalty
        reasons.append(f"低可信来源为主: -{penalty}")

    # Penalty for missing critical info
    missing_count = sum([
        1 if not vuln.get("description") else 0,
        1 if not vuln.get("cvss_score") else 0,
        1 if not vuln.get("published_at") else 0,
    ])
    if missing_count >= 2:
        penalty = missing_count * 5
        score -= penalty
        reasons.append(f"信息缺失严重: -{penalty}")

    # Cap at 100, floor at 0
    if score > 100:
        reasons.append(f"综合封顶为100")
    score = max(0.0, min(100.0, score))

    return score, reasons
