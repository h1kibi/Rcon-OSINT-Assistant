from sqlmodel import Session, text
from loguru import logger


def create_fts5(session: Session):
    """Create SQLite FTS5 virtual table for full-text search."""
    session.execute(text("""
        CREATE VIRTUAL TABLE IF NOT EXISTS vulnerabilities_fts USING fts5(
            cve_id, ghsa_id, osv_id, title, description,
            content='vulnerabilities',
            content_rowid='id'
        )
    """))
    session.commit()
    logger.info("FTS5 index created")


def create_triggers(session: Session):
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


def run_schema_migrations(session: Session):
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
    session.commit()
    logger.info("Schema migrations completed")


def run_migrations(session: Session):
    """Run all migrations."""
    create_fts5(session)
    create_triggers(session)
    run_schema_migrations(session)
