from sqlmodel import Session, text
from loguru import logger


def _ensure_schema_version(session: Session):
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """))
    session.commit()


def _get_applied_versions(session: Session) -> set[int]:
    rows = session.execute(text("SELECT version FROM schema_migrations")).fetchall()
    return {r[0] for r in rows}


def _mark_applied(session: Session, version: int):
    session.execute(
        text("INSERT INTO schema_migrations (version, applied_at) VALUES (:ver, datetime('now'))"),
        {"ver": version},
    )
    session.commit()


def create_fts5(session: Session):
    session.execute(text("""
        CREATE VIRTUAL TABLE IF NOT EXISTS vulnerabilities_fts USING fts5(
            cve_id, ghsa_id, osv_id, title, description,
            content='vulnerabilities',
            content_rowid='id'
        )
    """))
    session.commit()
    logger.info("FTS5 index created")


def run_migrations(session: Session):
    _ensure_schema_version(session)
    applied = _get_applied_versions(session)

    if 1 not in applied:
        _migrate_v1(session)
        _mark_applied(session, 1)

    if 2 not in applied:
        _create_sort_indexes(session)
        _mark_applied(session, 2)

    logger.info(f"Schema at version(s): {sorted(_get_applied_versions(session))}")


def _migrate_v1(session: Session):
    create_fts5(session)
    _create_fts_triggers(session)
    _run_schema_migrations(session)


def _create_fts_triggers(session: Session):
    """Create triggers to keep FTS5 index in sync."""
    session.execute(text("""
        CREATE TRIGGER IF NOT EXISTS vulnerabilities_ai AFTER INSERT ON vulnerabilities BEGIN
            INSERT INTO vulnerabilities_fts(rowid, cve_id, ghsa_id, osv_id, title, description)
            VALUES (new.id, new.cve_id, new.ghsa_id, new.osv_id, new.title, new.description);
        END
    """))
    session.commit()

    session.execute(text("""
        CREATE TRIGGER IF NOT EXISTS vulnerabilities_ad AFTER DELETE ON vulnerabilities BEGIN
            INSERT INTO vulnerabilities_fts(vulnerabilities_fts, rowid, cve_id, ghsa_id, osv_id, title, description)
            VALUES ('delete', old.id, old.cve_id, old.ghsa_id, old.osv_id, old.title, old.description);
        END
    """))
    session.commit()

    session.execute(text("""
        CREATE TRIGGER IF NOT EXISTS vulnerabilities_au AFTER UPDATE ON vulnerabilities BEGIN
            INSERT INTO vulnerabilities_fts(vulnerabilities_fts, rowid, cve_id, ghsa_id, osv_id, title, description)
            VALUES ('delete', old.id, old.cve_id, old.ghsa_id, old.osv_id, old.title, old.description);
            INSERT INTO vulnerabilities_fts(rowid, cve_id, ghsa_id, osv_id, title, description)
            VALUES (new.id, new.cve_id, new.ghsa_id, new.osv_id, new.title, new.description);
        END
    """))
    session.commit()
    logger.info("FTS5 triggers created")


def _run_schema_migrations(session: Session):
    """Lightweight SQLite schema migration for new columns."""
    vuln_cols = {row[1] for row in session.execute(text("PRAGMA table_info(vulnerabilities)"))}
    if "disclosed_at" not in vuln_cols:
        session.execute(text("ALTER TABLE vulnerabilities ADD COLUMN disclosed_at DATETIME"))
    if "disclosed_source" not in vuln_cols:
        session.execute(text("ALTER TABLE vulnerabilities ADD COLUMN disclosed_source VARCHAR DEFAULT ''"))
    session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_disclosed_at ON vulnerabilities(disclosed_at)"
    ))

    src_cols = {row[1] for row in session.execute(text("PRAGMA table_info(source_records)"))}
    if "published_at" not in src_cols:
        session.execute(text("ALTER TABLE source_records ADD COLUMN published_at DATETIME"))
    if "modified_at" not in src_cols:
        session.execute(text("ALTER TABLE source_records ADD COLUMN modified_at DATETIME"))
    if "url" not in src_cols:
        session.execute(text("ALTER TABLE source_records ADD COLUMN url VARCHAR DEFAULT ''"))
    if "title" not in src_cols:
        session.execute(text("ALTER TABLE source_records ADD COLUMN title VARCHAR DEFAULT ''"))
    session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_source_records_published_at ON source_records(published_at)"
    ))

    # AI Push Report tables (lightweight CREATE IF NOT EXISTS)
    for ddl in [
        """CREATE TABLE IF NOT EXISTS ai_push_reports (
            id INTEGER PRIMARY KEY,
            title VARCHAR DEFAULT '',
            status VARCHAR DEFAULT 'queued',
            trigger_type VARCHAR DEFAULT 'startup',
            rule_content TEXT DEFAULT '',
            ai_content TEXT DEFAULT '',
            final_content TEXT DEFAULT '',
            prompt TEXT DEFAULT '',
            context_json TEXT DEFAULT '',
            content_hash VARCHAR DEFAULT '',
            model VARCHAR DEFAULT '',
            error TEXT DEFAULT '',
            candidate_count INTEGER DEFAULT 0,
            high_risk_count INTEGER DEFAULT 0,
            new_high_risk_count INTEGER DEFAULT 0,
            generated_at DATETIME,
            optimized_at DATETIME,
            created_at DATETIME,
            updated_at DATETIME
        )""",
        """CREATE TABLE IF NOT EXISTS ai_push_report_items (
            id INTEGER PRIMARY KEY,
            report_id INTEGER,
            vulnerability_id INTEGER,
            vuln_key VARCHAR DEFAULT '',
            title VARCHAR DEFAULT '',
            disclosed_at DATETIME,
            disclosed_source VARCHAR DEFAULT '',
            action_value_score FLOAT DEFAULT 0,
            cvss_score FLOAT,
            is_kev BOOLEAN DEFAULT 0,
            created_at DATETIME
        )""",
        """CREATE TABLE IF NOT EXISTS high_risk_alerts (
            id INTEGER PRIMARY KEY,
            vulnerability_id INTEGER UNIQUE,
            first_report_id INTEGER,
            latest_report_id INTEGER,
            status VARCHAR DEFAULT 'unread',
            first_alerted_at DATETIME,
            last_alerted_at DATETIME,
            read_at DATETIME
        )""",
        """CREATE TABLE IF NOT EXISTS personal_library_entries (
            id INTEGER PRIMARY KEY,
            entry_type VARCHAR DEFAULT 'ai_push_report',
            report_id INTEGER,
            vulnerability_id INTEGER,
            title VARCHAR DEFAULT '',
            note TEXT DEFAULT '',
            tags VARCHAR DEFAULT '',
            pinned BOOLEAN DEFAULT 0,
            archived BOOLEAN DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME
        )""",
    ]:
        session.execute(text(ddl))

    session.commit()
    logger.info("Schema migrations completed")


def _create_sort_indexes(session: Session):
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS ix_vuln_score_sort ON vulnerabilities(status, action_value_score DESC, published_at DESC, id DESC)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_date_sort ON vulnerabilities(status, published_at DESC, action_value_score DESC, id DESC)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_cvss_sort ON vulnerabilities(status, cvss_score DESC, action_value_score DESC, id DESC)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_kev_sort ON vulnerabilities(is_kev, action_value_score DESC, published_at DESC)",
    ]:
        session.execute(text(idx_sql))
    session.commit()
    logger.info("Sort composite indexes created")
