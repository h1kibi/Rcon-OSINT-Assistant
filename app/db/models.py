from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime, func, UniqueConstraint


def _utcnow() -> datetime:
    """Return current UTC datetime (timezone-naive for SQLite compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Vulnerability(SQLModel, table=True):
    __tablename__ = "vulnerabilities"

    id: Optional[int] = Field(default=None, primary_key=True)
    primary_key_id: str = Field(index=True, unique=True)
    cve_id: Optional[str] = Field(default=None, index=True)
    ghsa_id: Optional[str] = Field(default=None, index=True)
    osv_id: Optional[str] = Field(default=None, index=True)
    title: str = Field(default="")
    description: str = Field(default="")
    severity: str = Field(default="UNKNOWN", index=True)
    cvss_score: Optional[float] = Field(default=None)
    cvss_vector: Optional[str] = Field(default=None)
    epss_score: Optional[float] = Field(default=None)
    epss_percentile: Optional[float] = Field(default=None)
    is_kev: bool = Field(default=False, index=True)
    kev_due_date: Optional[datetime] = Field(default=None)
    kev_known_ransomware: bool = Field(default=False)
    official_confirmed: bool = Field(default=False, index=True)
    has_patch: bool = Field(default=False, index=True)
    has_poc_signal: bool = Field(default=False, index=True)
    source_confidence_score: float = Field(default=50.0)
    source: str = Field(default="", index=True)
    action_value_score: float = Field(default=0.0, index=True)
    action_value_reason: str = Field(default="")
    disclosed_at: Optional[datetime] = Field(default=None, index=True)
    disclosed_source: str = Field(default="")
    published_at: Optional[datetime] = Field(default=None, index=True)
    modified_at: Optional[datetime] = Field(default=None)
    first_seen_at: Optional[datetime] = Field(default=None)
    last_seen_at: Optional[datetime] = Field(default=None)
    status: str = Field(default="unread", index=True)
    created_at: datetime = Field(
        sa_column=Column(DateTime, server_default=func.now())
    )
    updated_at: datetime = Field(
        sa_column=Column(DateTime, server_default=func.now(), onupdate=func.now())
    )


class AffectedProduct(SQLModel, table=True):
    __tablename__ = "affected_products"

    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: int = Field(foreign_key="vulnerabilities.id", index=True)
    vendor: str = Field(default="", index=True)
    product: str = Field(default="", index=True)
    version_start: Optional[str] = Field(default=None)
    version_end: Optional[str] = Field(default=None)
    fixed_version: Optional[str] = Field(default=None)
    cpe: Optional[str] = Field(default=None)
    package_ecosystem: Optional[str] = Field(default=None)
    package_name: Optional[str] = Field(default=None, index=True)


class VulnerabilityReference(SQLModel, table=True):
    __tablename__ = "vulnerability_references"
    __table_args__ = (UniqueConstraint("vulnerability_id", "url", name="uq_vuln_ref_url"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: int = Field(foreign_key="vulnerabilities.id", index=True)
    url: str = Field(default="")
    source: str = Field(default="")
    tags: str = Field(default="")


class SourceRecord(SQLModel, table=True):
    __tablename__ = "source_records"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "source", "source_id", name="uq_source_record_identity"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: Optional[int] = Field(
        default=None, foreign_key="vulnerabilities.id", index=True
    )
    source: str = Field(default="", index=True)
    source_id: str = Field(default="")
    source_type: str = Field(default="")
    raw_json: str = Field(default="")
    raw_html: str = Field(default="")
    published_at: Optional[datetime] = Field(default=None, index=True)
    modified_at: Optional[datetime] = Field(default=None)
    url: str = Field(default="")
    title: str = Field(default="")
    fetched_at: datetime = Field(default_factory=_utcnow)


class UserPreference(SQLModel, table=True):
    __tablename__ = "user_preferences"

    id: Optional[int] = Field(default=None, primary_key=True)
    watch_keywords: str = Field(default="")
    watch_vendors: str = Field(default="")
    watch_products: str = Field(default="")
    min_score_to_badge: int = Field(default=70)
    min_score_to_notify: int = Field(default=80)
    refresh_interval_minutes: int = Field(default=60)
    quiet_hours_enabled: bool = Field(default=True)
    quiet_hours_start: str = Field(default="23:00")
    quiet_hours_end: str = Field(default="08:00")


class Notification(SQLModel, table=True):
    __tablename__ = "notifications"

    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: int = Field(foreign_key="vulnerabilities.id", index=True)
    notification_type: str = Field(default="new_high_value")
    status: str = Field(default="pending")
    created_at: datetime = Field(default_factory=_utcnow)
    read_at: Optional[datetime] = Field(default=None)


class CollectorStatus(SQLModel, table=True):
    __tablename__ = "collector_status"

    id: Optional[int] = Field(default=None, primary_key=True)
    source_name: str = Field(index=True, unique=True)
    enabled: bool = Field(default=True)
    initialized: bool = Field(default=False)
    last_success_sync_at: Optional[datetime] = Field(default=None)
    last_error_at: Optional[datetime] = Field(default=None)
    last_error: str = Field(default="")
    last_cursor: str = Field(default="")
    items_count: int = Field(default=0)
    health_status: str = Field(default="unknown")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class VulnerabilityChange(SQLModel, table=True):
    __tablename__ = "vulnerability_changes"

    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: int = Field(foreign_key="vulnerabilities.id", index=True)
    field_name: str = Field(default="")
    old_value: str = Field(default="")
    new_value: str = Field(default="")
    source: str = Field(default="")
    changed_at: datetime = Field(default_factory=_utcnow)


class AIAnalysisHistory(SQLModel, table=True):
    __tablename__ = "ai_analysis_history"

    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: int = Field(foreign_key="vulnerabilities.id", index=True)
    cve_id: str = Field(default="", index=True)
    analysis_content: str = Field(default="")
    protocol: str = Field(default="")
    model: str = Field(default="")
    created_at: datetime = Field(default_factory=_utcnow)


class AIPushReport(SQLModel, table=True):
    __tablename__ = "ai_push_reports"

    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(default="")
    status: str = Field(default="queued", index=True)
    trigger_type: str = Field(default="startup", index=True)
    rule_content: str = Field(default="")
    ai_content: str = Field(default="")
    final_content: str = Field(default="")
    prompt: str = Field(default="")
    context_json: str = Field(default="")
    content_hash: str = Field(default="", index=True)
    model: str = Field(default="")
    error: str = Field(default="")
    candidate_count: int = Field(default=0)
    high_risk_count: int = Field(default=0)
    new_high_risk_count: int = Field(default=0)
    generated_at: Optional[datetime] = Field(default=None, index=True)
    optimized_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class AIPushReportItem(SQLModel, table=True):
    __tablename__ = "ai_push_report_items"

    id: Optional[int] = Field(default=None, primary_key=True)
    report_id: int = Field(foreign_key="ai_push_reports.id", index=True)
    vulnerability_id: int = Field(foreign_key="vulnerabilities.id", index=True)
    vuln_key: str = Field(default="", index=True)
    title: str = Field(default="")
    disclosed_at: Optional[datetime] = Field(default=None, index=True)
    disclosed_source: str = Field(default="")
    action_value_score: float = Field(default=0.0)
    cvss_score: Optional[float] = Field(default=None)
    is_kev: bool = Field(default=False)
    created_at: datetime = Field(default_factory=_utcnow)


class HighRiskAlert(SQLModel, table=True):
    __tablename__ = "high_risk_alerts"

    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: int = Field(foreign_key="vulnerabilities.id", index=True, unique=True)
    first_report_id: Optional[int] = Field(default=None, foreign_key="ai_push_reports.id")
    latest_report_id: Optional[int] = Field(default=None, foreign_key="ai_push_reports.id")
    status: str = Field(default="unread", index=True)
    first_alerted_at: datetime = Field(default_factory=_utcnow)
    last_alerted_at: datetime = Field(default_factory=_utcnow)
    read_at: Optional[datetime] = Field(default=None)


class PersonalLibraryEntry(SQLModel, table=True):
    __tablename__ = "personal_library_entries"

    id: Optional[int] = Field(default=None, primary_key=True)
    entry_type: str = Field(default="ai_push_report", index=True)
    report_id: Optional[int] = Field(default=None, foreign_key="ai_push_reports.id", index=True)
    vulnerability_id: Optional[int] = Field(default=None, foreign_key="vulnerabilities.id", index=True)
    title: str = Field(default="")
    note: str = Field(default="")
    tags: str = Field(default="")
    pinned: bool = Field(default=False)
    archived: bool = Field(default=False)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
