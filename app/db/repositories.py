from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Session, select, func, col
from app.db.models import (
    Vulnerability, AffectedProduct, VulnerabilityReference,
    SourceRecord, UserPreference, Notification, CollectorStatus,
    VulnerabilityChange, AIAnalysisHistory,
    AIPushReport, AIPushReportItem, HighRiskAlert, PersonalLibraryEntry,
    _utcnow,
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
    sort: str = "smart",
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

    # ── Rankings (first-class ORDER BY keys, not mixed into score) ──
    ignored_rank = case(
        (Vulnerability.status == "ignored", 1),
        else_=0,
    )
    watched_rank = case(
        (Vulnerability.status == "watched", 1),
        else_=0,
    )
    kev_rank = case(
        (Vulnerability.is_kev == True, 1),  # noqa: E712
        else_=0,
    )
    poc_rank = case(
        (Vulnerability.has_poc_signal == True, 1),  # noqa: E712
        else_=0,
    )

    # ── Null-safe score fields ──
    score = sa_func.coalesce(Vulnerability.action_value_score, 0)
    cvss = sa_func.coalesce(Vulnerability.cvss_score, 0)
    epss_pct = sa_func.coalesce(Vulnerability.epss_percentile, 0)

    if sort == "smart":
        # ── Smart: action_value_score + continuous recency decay + confidence ──
        age_hours = (sa_func.julianday("now") - sa_func.julianday(
            sa_func.coalesce(
                Vulnerability.disclosed_at,
                Vulnerability.published_at,
                Vulnerability.first_seen_at,
            )
        )) * 24.0

        recency_decay = case(
            (age_hours < 168, 8.0 * (1.0 - age_hours / 168.0)),
            else_=0,
        )
        confidence_bonus = case(
            (Vulnerability.source_confidence_score >= 80, 3),
            (Vulnerability.source_confidence_score >= 60, 1),
            else_=0,
        )

        smart_score = score + recency_decay + confidence_bonus

        stmt = stmt.order_by(
            ignored_rank.asc(),
            watched_rank.desc(),
            smart_score.desc(),
            kev_rank.desc(),
            epss_pct.desc(),
            poc_rank.desc(),
            cvss.desc(),
            effective_date.desc(),
            Vulnerability.id.desc(),
        )

    elif sort == "date_desc":
        stmt = stmt.order_by(
            ignored_rank.asc(),
            effective_date.desc(),
            score.desc(),
            Vulnerability.id.desc(),
        )

    elif sort == "date_asc":
        stmt = stmt.order_by(
            ignored_rank.asc(),
            effective_date.asc(),
            score.desc(),
            Vulnerability.id.desc(),
        )

    elif sort == "cvss_desc":
        stmt = stmt.order_by(
            ignored_rank.asc(),
            cvss.desc(),
            score.desc(),
            epss_pct.desc(),
            effective_date.desc(),
            Vulnerability.id.desc(),
        )

    elif sort == "cvss_asc":
        stmt = stmt.order_by(
            ignored_rank.asc(),
            cvss.asc(),
            score.desc(),
            effective_date.desc(),
            Vulnerability.id.desc(),
        )

    elif sort == "score_asc":
        stmt = stmt.order_by(
            ignored_rank.asc(),
            score.asc(),
            effective_date.desc(),
            Vulnerability.id.desc(),
        )

    else:
        # score_desc fallback
        stmt = stmt.order_by(
            ignored_rank.asc(),
            score.desc(),
            kev_rank.desc(),
            epss_pct.desc(),
            effective_date.desc(),
            Vulnerability.id.desc(),
        )

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
        _affected_product_key(e): e for e in existing
    }

    for p in products:
        vendor = p.get("vendor", "")
        product = p.get("product", "")
        pkg_name = p.get("package_name", "")
        key = _affected_product_key_from_dict(p, vendor, product, pkg_name)

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
        existing.initialized = cs.initialized or existing.initialized
        existing.items_count = cs.items_count or existing.items_count
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


# ─── AI Push Report Repository ─────────────────────────────────────

def create_ai_push_report(session: Session, trigger_type: str) -> AIPushReport:
    report = AIPushReport(
        title="AI推送：最新高危漏洞简报",
        status="queued",
        trigger_type=trigger_type,
        created_at=_utcnow(),
        updated_at=_utcnow(),
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return report


def mark_ai_push_report_error(session: Session, report_id: int, error: str):
    report = session.get(AIPushReport, report_id)
    if not report:
        return
    report.status = "error"
    report.error = error[:2000]
    report.updated_at = _utcnow()
    session.add(report)
    session.commit()


def save_ai_push_report_ready(
    session: Session, report_id: int, *, rule_content: str,
    ai_content: str, final_content: str, prompt: str,
    context_json: str, content_hash: str, model: str,
    candidate_count: int, high_risk_count: int,
    new_high_risk_count: int, status: str, error: str = "",
):
    report = session.get(AIPushReport, report_id)
    if not report:
        return
    report.rule_content = rule_content
    report.ai_content = ai_content
    report.final_content = final_content
    report.prompt = prompt
    report.context_json = context_json
    report.content_hash = content_hash
    report.model = model
    report.candidate_count = candidate_count
    report.high_risk_count = high_risk_count
    report.new_high_risk_count = new_high_risk_count
    report.status = status
    if error:
        report.error = error[:2000]
    report.generated_at = report.generated_at or _utcnow()
    if status == "ready_ai":
        report.optimized_at = _utcnow()
    report.updated_at = _utcnow()
    session.add(report)
    session.commit()


def add_ai_push_report_items(session: Session, report_id: int, items: list[dict]):
    for item in items:
        vid = item.get("id")
        if not vid:
            continue
        # disclosed_at_raw may be str or datetime
        disclosed_val = item.get("disclosed_at_raw")
        if isinstance(disclosed_val, str):
            try:
                disclosed_val = datetime.strptime(disclosed_val.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                disclosed_val = None
        row = AIPushReportItem(
            report_id=report_id,
            vulnerability_id=vid,
            vuln_key=item.get("key", ""),
            title=item.get("title", ""),
            disclosed_at=disclosed_val if isinstance(disclosed_val, datetime) else None,
            disclosed_source=item.get("disclosed_source", ""),
            action_value_score=item.get("action_value_score") or 0,
            cvss_score=item.get("cvss_score"),
            is_kev=bool(item.get("is_kev")),
            created_at=_utcnow(),
        )
        session.add(row)
    session.commit()


def upsert_high_risk_alerts(session: Session, report_id: int, items: list[dict]) -> int:
    new_count = 0
    for item in items:
        vid = item.get("id")
        if not vid:
            continue
        existing = session.exec(
            select(HighRiskAlert).where(HighRiskAlert.vulnerability_id == vid)
        ).first()
        if existing:
            existing.latest_report_id = report_id
            existing.last_alerted_at = _utcnow()
            session.add(existing)
        else:
            session.add(HighRiskAlert(
                vulnerability_id=vid,
                first_report_id=report_id,
                latest_report_id=report_id,
                status="unread",
                first_alerted_at=_utcnow(),
                last_alerted_at=_utcnow(),
            ))
            new_count += 1
    session.commit()
    return new_count


def count_unread_high_risk_alerts(session: Session) -> int:
    return session.exec(
        select(func.count(HighRiskAlert.id)).where(HighRiskAlert.status == "unread")
    ).one()


def mark_report_alerts_read(session: Session, report_id: int):
    item_vuln_ids = session.exec(
        select(AIPushReportItem.vulnerability_id).where(AIPushReportItem.report_id == report_id)
    ).all()
    if not item_vuln_ids:
        return
    alerts = session.exec(
        select(HighRiskAlert).where(HighRiskAlert.vulnerability_id.in_(item_vuln_ids))
    ).all()
    now = _utcnow()
    for a in alerts:
        a.status = "read"
        a.read_at = now
        session.add(a)
    session.commit()


def get_latest_ready_ai_push_report(session: Session) -> Optional[AIPushReport]:
    return session.exec(
        select(AIPushReport)
        .where(AIPushReport.status.in_(["ready_rule", "ready_ai"]))
        .order_by(AIPushReport.updated_at.desc())
        .limit(1)
    ).first()


def get_latest_ai_push_report(session: Session) -> Optional[AIPushReport]:
    return session.exec(
        select(AIPushReport).order_by(AIPushReport.updated_at.desc()).limit(1)
    ).first()


def count_unalerted_high_risk_candidates(
    session: Session, days: int = 14, min_score: float = 70.0
) -> int:
    from datetime import timedelta
    from sqlalchemy import func as sa_func
    eff = sa_func.coalesce(Vulnerability.disclosed_at, Vulnerability.published_at,
                            Vulnerability.first_seen_at)
    cutoff = _utcnow() - timedelta(days=days)
    already = session.exec(select(HighRiskAlert.vulnerability_id)).all()
    already_ids = {r for r in already if r}
    stmt = (
        select(func.count(Vulnerability.id))
        .where(Vulnerability.status != "ignored")
        .where(eff >= cutoff)
        .where(
            (Vulnerability.action_value_score >= min_score) |
            (Vulnerability.cvss_score >= 8.0) |
            (Vulnerability.is_kev == True) |  # noqa: E712
            (Vulnerability.epss_percentile >= 0.9) |
            (Vulnerability.has_poc_signal == True)  # noqa: E712
        )
    )
    if already_ids:
        stmt = stmt.where(~Vulnerability.id.in_(already_ids))
    return session.exec(stmt).one()


def add_personal_library_report_entry(
    session: Session, report_id: int, title: str
):
    existing = session.exec(
        select(PersonalLibraryEntry).where(
            PersonalLibraryEntry.entry_type == "ai_push_report",
            PersonalLibraryEntry.report_id == report_id,
        )
    ).first()
    if existing:
        existing.title = title or existing.title
        existing.updated_at = _utcnow()
        session.add(existing)
    else:
        session.add(PersonalLibraryEntry(
            entry_type="ai_push_report",
            report_id=report_id,
            title=title,
            created_at=_utcnow(),
            updated_at=_utcnow(),
        ))
    session.commit()


def get_personal_library_entries(
    session: Session, entry_type: str | None = None
) -> list[PersonalLibraryEntry]:
    stmt = select(PersonalLibraryEntry).where(PersonalLibraryEntry.archived == False)
    if entry_type:
        stmt = stmt.where(PersonalLibraryEntry.entry_type == entry_type)
    return list(session.exec(stmt.order_by(PersonalLibraryEntry.created_at.desc())).all())


def _affected_product_key(ap: AffectedProduct) -> tuple:
    return (
        _norm(ap.vendor), _norm(ap.product), _norm(ap.package_ecosystem),
        _norm(ap.package_name), _norm(ap.cpe),
        _norm(ap.version_start), _norm(ap.version_end), _norm(ap.fixed_version),
    )


def _affected_product_key_from_dict(p: dict, vendor: str, product: str, pkg_name: str) -> tuple:
    return (
        _norm(vendor), _norm(product),
        _norm(p.get("package_ecosystem", "")),
        _norm(pkg_name),
        _norm(p.get("cpe", "")),
        _norm(p.get("version_start", "")),
        _norm(p.get("version_end", "")),
        _norm(p.get("fixed_version", "")),
    )


def _norm(s):
    return (s or "").strip().lower()
