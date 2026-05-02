from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Session, select, func, col
from app.db.models import (
    Vulnerability, AffectedProduct, VulnerabilityReference,
    SourceRecord, UserPreference, Notification, CollectorStatus,
    VulnerabilityChange, AIAnalysisHistory, _utcnow,
)


# ─── Vulnerability Repository ───────────────────────────────────────

def upsert_vulnerability(session: Session, vuln: Vulnerability) -> Vulnerability:
    """Insert or update a vulnerability by primary_key_id."""
    existing = session.exec(
        select(Vulnerability).where(
            Vulnerability.primary_key_id == vuln.primary_key_id
        )
    ).first()

    if existing:
        for key, value in vuln.model_dump(exclude={"id", "created_at", "updated_at"}).items():
            if value is not None:
                setattr(existing, key, value)
        existing.updated_at = _utcnow()
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing
    else:
        vuln.first_seen_at = vuln.first_seen_at or _utcnow()
        vuln.last_seen_at = vuln.last_seen_at or _utcnow()
        session.add(vuln)
        session.commit()
        session.refresh(vuln)
        return vuln


def get_vulnerabilities(
    session: Session,
    status: Optional[str] = None,
    is_kev: Optional[bool] = None,
    min_cvss: Optional[float] = None,
    min_epss_percentile: Optional[float] = None,
    has_poc: Optional[bool] = None,
    has_patch: Optional[bool] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    source: Optional[str] = None,
    days: Optional[int] = None,
    keyword: Optional[str] = None,
    sort: str = "score_desc",
    limit: int = 500,
    offset: int = 0,
) -> list[Vulnerability]:
    """Query vulnerabilities with filters."""
    stmt = select(Vulnerability)

    if status:
        stmt = stmt.where(Vulnerability.status == status)
    if is_kev is not None:
        stmt = stmt.where(Vulnerability.is_kev == is_kev)
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_score >= min_cvss)
    if min_epss_percentile is not None:
        stmt = stmt.where(Vulnerability.epss_percentile >= min_epss_percentile)
    if has_poc is not None:
        stmt = stmt.where(Vulnerability.has_poc_signal == has_poc)
    if has_patch is not None:
        stmt = stmt.where(Vulnerability.has_patch == has_patch)
    if days is not None:
        cutoff = _utcnow() - timedelta(days=days)
        stmt = stmt.where(Vulnerability.published_at >= cutoff)

    # Product/vendor filter
    if vendor or product:
        subq = select(AffectedProduct.vulnerability_id)
        if vendor:
            subq = subq.where(AffectedProduct.vendor.contains(vendor))
        if product:
            subq = subq.where(
                (AffectedProduct.product.contains(product)) |
                (AffectedProduct.package_name.contains(product))
            )
        affected_ids = {r for r in session.exec(subq).all()}
        if affected_ids:
            stmt = stmt.where(Vulnerability.id.in_(affected_ids))
        else:
            return []

    # Keyword search (independent of vendor/product)
    if keyword:
        import re
        from sqlalchemy import or_
        kw = keyword.strip()

        conditions = []

        # GHSA ID pattern: GHSA-xxxx-xxxx-xxxx
        if 'GHSA' in kw.upper() or 'ghsa' in kw.lower():
            conditions.append(Vulnerability.ghsa_id.contains(kw))

        # CVE ID pattern: CVE-2026-2892, cve-2026-2892, 2026-2892, 20262892
        cve_match = re.search(r'(\d{4})[-\s]?(\d{4,})', kw)

        if cve_match:
            year = cve_match.group(1)
            num = cve_match.group(2)
            cve_standard = f"CVE-{year}-{num}"

            conditions.append(Vulnerability.cve_id == cve_standard)
            conditions.append(Vulnerability.cve_id.contains(f"{year}-{num}"))
            if len(num) >= 4:
                conditions.append(Vulnerability.cve_id.contains(num))
        else:
            # Search in CVE ID, GHSA ID, OSV ID
            conditions.append(Vulnerability.cve_id.contains(kw))
            conditions.append(Vulnerability.ghsa_id.contains(kw))
            conditions.append(Vulnerability.osv_id.contains(kw))

        # Always search in title and description
        conditions.append(Vulnerability.title.contains(kw))
        conditions.append(Vulnerability.description.contains(kw))

        stmt = stmt.where(or_(*conditions))
    if source:
        subq_source = select(SourceRecord.vulnerability_id).where(
            SourceRecord.source.contains(source)
        )
        source_ids = {r for r in session.exec(subq_source).all()}
        if source_ids:
            stmt = stmt.where(Vulnerability.id.in_(source_ids))
        else:
            return []

    # Effective date for sorting: disclosed > published > first_seen
    from sqlalchemy import func as sa_func
    effective_date = sa_func.coalesce(
        Vulnerability.disclosed_at,
        Vulnerability.published_at,
        Vulnerability.first_seen_at,
    )

    # Sorting
    from sqlalchemy import case

    # Ignored items always go to bottom
    ignored_penalty = case(
        (Vulnerability.status == "ignored", -100000),
        else_=0,
    )

    if sort == "smart":
        # Smart: composite score + recency
        now = datetime.utcnow()
        d1 = now - timedelta(days=1)
        d3 = now - timedelta(days=3)
        d7 = now - timedelta(days=7)
        d30 = now - timedelta(days=30)

        recency_bonus = case(
            (effective_date >= d1, 50),
            (effective_date >= d3, 35),
            (effective_date >= d7, 20),
            (effective_date >= d30, 8),
            else_=0,
        )
        severity_group = case(
            (Vulnerability.cvss_score >= 9.0, 3),
            (Vulnerability.cvss_score >= 7.0, 3),
            (Vulnerability.cvss_score >= 4.0, 2),
            else_=1,
        )
        high_risk_recency = case(
            (Vulnerability.cvss_score >= 7.0, recency_bonus * 2),
            (Vulnerability.cvss_score >= 4.0, recency_bonus),
            else_=recency_bonus / 2,
        )
        smart_score = (
            Vulnerability.action_value_score * 2
            + high_risk_recency
            + severity_group * 10
            + ignored_penalty
        )
        order = smart_score.desc()

    elif sort == "date_desc":
        # Ignored last, then newest first
        order = (Vulnerability.status == "ignored").asc(), effective_date.desc()

    elif sort == "date_asc":
        order = (Vulnerability.status == "ignored").asc(), effective_date.asc()

    elif sort == "cvss_desc":
        order = (Vulnerability.status == "ignored").asc(), Vulnerability.cvss_score.desc()

    elif sort == "cvss_asc":
        order = (Vulnerability.status == "ignored").asc(), Vulnerability.cvss_score.asc()

    elif sort == "score_asc":
        order = (Vulnerability.status == "ignored").asc(), Vulnerability.action_value_score.asc()

    else:
        order = (Vulnerability.status == "ignored").asc(), Vulnerability.action_value_score.desc()

    stmt = stmt.order_by(*order) if isinstance(order, tuple) else stmt.order_by(order)
    stmt = stmt.offset(offset).limit(limit)
    return list(session.exec(stmt).all())


def get_vulnerability_by_id(session: Session, vuln_id: int) -> Optional[Vulnerability]:
    return session.get(Vulnerability, vuln_id)


def update_status(session: Session, vuln_id: int, status: str):
    vuln = session.get(Vulnerability, vuln_id)
    if vuln:
        vuln.status = status
        vuln.updated_at = _utcnow()
        session.add(vuln)
        session.commit()


def count_unread_high_value(session: Session, min_score: int = 70) -> int:
    """Count unread vulnerabilities with score >= min_score."""
    stmt = select(func.count(Vulnerability.id)).where(
        (Vulnerability.status == "unread") &
        (Vulnerability.action_value_score >= min_score)
    )
    return session.exec(stmt).one()


def search_fts(session: Session, query: str, limit: int = 100) -> list[int]:
    """Full-text search returning vulnerability IDs."""
    try:
        from sqlmodel import text
        result = session.execute(
            text(
                "SELECT rowid FROM vulnerabilities_fts "
                "WHERE vulnerabilities_fts MATCH :q "
                "ORDER BY rank LIMIT :lim"
            ).bindparams(q=query, lim=limit)
        )
        return [row[0] for row in result]
    except Exception:
        return []


# ─── Affected Product Repository ────────────────────────────────────

def save_affected_products(
    session: Session, vuln_id: int, products: list[dict]
):
    if not products:
        products = []
    existing = session.exec(
        select(AffectedProduct).where(
            AffectedProduct.vulnerability_id == vuln_id
        )
    ).all()
    existing_keys = {
        (e.vendor, e.product, e.package_name): e for e in existing
    }

    for p in products:
        vendor = p.get("vendor", "")
        product = p.get("product", "")
        pkg_name = p.get("package_name", "")
        key = (vendor, product, pkg_name)

        if key in existing_keys:
            ap = existing_keys[key]
            ap.version_start = p.get("version_start") or ap.version_start
            ap.version_end = p.get("version_end") or ap.version_end
            ap.fixed_version = p.get("fixed_version") or ap.fixed_version
            ap.cpe = p.get("cpe") or ap.cpe
            ap.package_ecosystem = p.get("package_ecosystem") or ap.package_ecosystem
        else:
            ap = AffectedProduct(
                vulnerability_id=vuln_id,
                vendor=vendor,
                product=product,
                version_start=p.get("version_start"),
                version_end=p.get("version_end"),
                fixed_version=p.get("fixed_version"),
                cpe=p.get("cpe"),
                package_ecosystem=p.get("package_ecosystem"),
                package_name=pkg_name,
            )
            existing_keys[key] = ap
        session.add(ap)
    session.commit()


def get_affected_products(session: Session, vuln_id: int) -> list[AffectedProduct]:
    stmt = select(AffectedProduct).where(
        AffectedProduct.vulnerability_id == vuln_id
    )
    return list(session.exec(stmt).all())


# ─── References Repository ──────────────────────────────────────────

def save_references(session: Session, vuln_id: int, refs: list[dict]):
    if not refs:
        refs = []
    existing = session.exec(
        select(VulnerabilityReference).where(
            VulnerabilityReference.vulnerability_id == vuln_id
        )
    ).all()
    existing_urls = {e.url for e in existing}

    for r in refs:
        url = r.get("url", "")
        if url and url not in existing_urls:
            vr = VulnerabilityReference(
                vulnerability_id=vuln_id,
                url=url,
                source=r.get("source", ""),
                tags=r.get("tags", ""),
            )
            session.add(vr)
            existing_urls.add(url)
    session.commit()


def get_references(session: Session, vuln_id: int) -> list[VulnerabilityReference]:
    stmt = select(VulnerabilityReference).where(
        VulnerabilityReference.vulnerability_id == vuln_id
    )
    return list(session.exec(stmt).all())


# ─── Source Record Repository ───────────────────────────────────────

def save_source_record(session: Session, record: SourceRecord):
    existing = session.exec(
        select(SourceRecord).where(
            SourceRecord.vulnerability_id == record.vulnerability_id,
            SourceRecord.source == record.source,
            SourceRecord.source_id == record.source_id,
        )
    ).first()
    if existing:
        existing.raw_json = record.raw_json or existing.raw_json
        existing.raw_html = record.raw_html or existing.raw_html
        existing.published_at = record.published_at or existing.published_at
        existing.modified_at = record.modified_at or existing.modified_at
        existing.url = record.url or existing.url
        existing.title = record.title or existing.title
        existing.fetched_at = record.fetched_at
        session.add(existing)
    else:
        session.add(record)
    session.commit()


def get_source_records(session: Session, vuln_id: int) -> list[SourceRecord]:
    stmt = select(SourceRecord).where(
        SourceRecord.vulnerability_id == vuln_id
    )
    return list(session.exec(stmt).all())


# ─── Collector Status Repository ────────────────────────────────────

def upsert_collector_status(session: Session, cs: CollectorStatus):
    existing = session.exec(
        select(CollectorStatus).where(
            CollectorStatus.source_name == cs.source_name
        )
    ).first()
    if existing:
        existing.last_success_sync_at = cs.last_success_sync_at
        existing.last_error_at = cs.last_error_at
        existing.last_error = cs.last_error
        existing.last_cursor = cs.last_cursor
        existing.health_status = cs.health_status
        existing.enabled = cs.enabled
        existing.updated_at = _utcnow()
        session.add(existing)
        session.commit()
    else:
        session.add(cs)
        session.commit()


def get_all_collector_status(session: Session) -> list[CollectorStatus]:
    return list(session.exec(select(CollectorStatus)).all())


# ─── User Preference Repository ─────────────────────────────────────

def get_preferences(session: Session) -> UserPreference:
    pref = session.exec(select(UserPreference)).first()
    if not pref:
        pref = UserPreference()
        session.add(pref)
        session.commit()
        session.refresh(pref)
    return pref


def update_preferences(session: Session, **kwargs):
    pref = get_preferences(session)
    for key, value in kwargs.items():
        if hasattr(pref, key):
            setattr(pref, key, value)
    session.add(pref)
    session.commit()


# ─── Notification Repository ────────────────────────────────────────

def create_notification(session: Session, vuln_id: int, ntype: str = "new_high_value"):
    notif = Notification(
        vulnerability_id=vuln_id,
        notification_type=ntype,
    )
    session.add(notif)
    session.commit()


# ─── Vulnerability Change Repository ────────────────────────────────

def log_change(
    session: Session, vuln_id: int, field_name: str,
    old_value: str, new_value: str, source: str = ""
):
    vc = VulnerabilityChange(
        vulnerability_id=vuln_id,
        field_name=field_name,
        old_value=old_value,
        new_value=new_value,
        source=source,
    )
    session.add(vc)
    session.commit()


# ─── AI Analysis History Repository ────────────────────────────────

def save_ai_analysis(session: Session, vuln_id: int, cve_id: str,
                     content: str, protocol: str = "", model: str = ""):
    """Save AI analysis result for a vulnerability."""
    history = AIAnalysisHistory(
        vulnerability_id=vuln_id,
        cve_id=cve_id,
        analysis_content=content,
        protocol=protocol,
        model=model,
    )
    session.add(history)
    session.commit()
    return history


def get_ai_analysis_history(session: Session, vuln_id: int) -> list[AIAnalysisHistory]:
    """Get all AI analysis history for a vulnerability."""
    stmt = (
        select(AIAnalysisHistory)
        .where(AIAnalysisHistory.vulnerability_id == vuln_id)
        .order_by(AIAnalysisHistory.created_at.desc())
    )
    return list(session.exec(stmt).all())


def get_latest_ai_analysis(session: Session, vuln_id: int) -> Optional[AIAnalysisHistory]:
    """Get the latest AI analysis for a vulnerability."""
    stmt = (
        select(AIAnalysisHistory)
        .where(AIAnalysisHistory.vulnerability_id == vuln_id)
        .order_by(AIAnalysisHistory.created_at.desc())
    )
    return session.exec(stmt).first()
