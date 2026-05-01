from datetime import datetime, timezone
from loguru import logger
from sqlmodel import Session, select, col, func
from app.collectors.base import RawAdvisory
from app.db import repositories as repo
from app.db.models import SourceRecord, CollectorStatus, Vulnerability
from app.pipeline.normalizer import normalize
from app.pipeline.deduplicator import deduplicate
from app.pipeline.scorer import calculate_score, ScorerConfig
from app.pipeline.source_confidence import get_confidence


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def run_sync_service(
    session: Session,
    collectors: dict,
    epss_collector,
    scorer_config: ScorerConfig,
):
    """Main sync pipeline: fetch → normalize → deduplicate → score → persist."""
    all_raw: list[RawAdvisory] = []

    # Fetch collector status once outside the loop
    status_list = repo.get_all_collector_status(session)
    status_map = {s.source_name: s for s in status_list}

    # Check if database has any data (first run detection)
    vuln_count = session.exec(select(func.count(Vulnerability.id))).one()
    is_first_run = vuln_count < 100

    for name, collector in collectors.items():
        if not collector.source_name:
            continue
        try:
            st = status_map.get(name)
            since = None
            if st and st.last_success_sync_at and collector.supports_incremental and not is_first_run:
                since = st.last_success_sync_at

            raw_list = collector.fetch_since(since)
            all_raw.extend(raw_list)

            repo.upsert_collector_status(session, CollectorStatus(
                source_name=name,
                enabled=True,
                last_success_sync_at=_utcnow(),
                health_status="healthy",
                last_cursor=_utcnow().isoformat(),
            ))
        except Exception as e:
            logger.error(f"Collector {name} failed: {e}")
            repo.upsert_collector_status(session, CollectorStatus(
                source_name=name,
                enabled=True,
                last_error_at=_utcnow(),
                last_error=str(e),
                health_status="error",
            ))

    logger.info(f"Total raw advisories: {len(all_raw)}")

    # Normalize
    normalized = normalize(all_raw, collectors)
    logger.info(f"Normalized: {len(normalized)}")

    # Deduplicate
    deduped = deduplicate(normalized)
    logger.info(f"Deduplicated: {len(deduped)}")

    # Enrich with EPSS
    cve_ids = [v.cve_id for v in deduped if v.cve_id]
    if cve_ids and epss_collector:
        try:
            epss_data = epss_collector.enrich(cve_ids)
            for v in deduped:
                if v.cve_id and v.cve_id in epss_data:
                    v.epss_score = epss_data[v.cve_id].get("epss_score")
                    v.epss_percentile = epss_data[v.cve_id].get("epss_percentile")
        except Exception as e:
            logger.error(f"EPSS enrichment failed: {e}")

    # Score and persist
    for nv in deduped:
        vuln_dict = {
            "is_kev": nv.is_kev,
            "epss_percentile": nv.epss_percentile,
            "cvss_score": nv.cvss_score,
            "published_at": nv.published_at,
            "official_confirmed": nv.official_confirmed,
            "has_patch": nv.has_patch,
            "has_poc_signal": nv.has_poc_signal,
            "source": nv.source,
            "source_confidence_score": nv.source_confidence_score,
            "title": nv.title,
            "description": nv.description,
            "affected_products": nv.affected_products,
        }
        score, reasons = calculate_score(vuln_dict, scorer_config)

        existing = session.exec(
            select(Vulnerability).where(
                Vulnerability.primary_key_id == nv.primary_key_id
            )
        ).first()
        is_new = existing is None

        vuln = Vulnerability(
            primary_key_id=nv.primary_key_id,
            cve_id=nv.cve_id,
            ghsa_id=nv.ghsa_id,
            osv_id=nv.osv_id,
            title=nv.title[:300] if nv.title else "",
            description=nv.description[:5000] if nv.description else "",
            severity=nv.severity,
            cvss_score=nv.cvss_score,
            cvss_vector=nv.cvss_vector,
            epss_score=nv.epss_score,
            epss_percentile=nv.epss_percentile,
            is_kev=nv.is_kev,
            kev_due_date=nv.kev_due_date,
            kev_known_ransomware=nv.kev_known_ransomware,
            official_confirmed=nv.official_confirmed,
            has_patch=nv.has_patch,
            has_poc_signal=nv.has_poc_signal,
            source_confidence_score=nv.source_confidence_score,
            action_value_score=score,
            action_value_reason="\n".join(reasons),
            published_at=nv.published_at,
            modified_at=nv.modified_at,
            source=nv.source,
            last_seen_at=_utcnow(),
        )
        saved = repo.upsert_vulnerability(session, vuln)

        # Save source record (dedup by vuln+source)
        repo.save_source_record(session, SourceRecord(
            vulnerability_id=saved.id,
            source=nv.source,
            source_id=nv.primary_key_id,
            source_type="api",
            raw_json=nv.raw_json,
            fetched_at=_utcnow(),
        ))

        # Save affected products (dedup by vendor+product+pkg)
        if nv.affected_products:
            repo.save_affected_products(session, saved.id, nv.affected_products)

        # Save references (dedup by url)
        if nv.references:
            repo.save_references(session, saved.id, nv.references)

        # Create notification for new high-value vulns
        if is_new and score >= 70:
            repo.create_notification(session, saved.id)

    logger.info(f"Sync complete: processed {len(deduped)} vulnerabilities")
