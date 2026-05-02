from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class RawAdvisory:
    """Raw advisory data from any source."""
    source: str
    source_id: str
    source_type: str
    raw_data: dict[str, Any]
    fetched_at: datetime = field(default_factory=_utcnow)


@dataclass
class NormalizedVulnerability:
    """Unified vulnerability format after normalization."""
    primary_key_id: str
    cve_id: str | None = None
    ghsa_id: str | None = None
    osv_id: str | None = None
    title: str = ""
    description: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_due_date: datetime | None = None
    kev_known_ransomware: bool = False
    official_confirmed: bool = False
    has_patch: bool = False
    has_poc_signal: bool = False
    cwe_ids: list[str] = field(default_factory=list)
    cpe_list: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    affected_products: list[dict] = field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    disclosed_at: datetime | None = None
    disclosed_source: str = ""
    source: str = ""
    source_confidence_score: float = 50.0
    raw_json: str = ""


@dataclass
class CollectorResult:
    """Unified return for all collector fetch operations."""
    source: str
    ok: bool
    items: list[RawAdvisory] = field(default_factory=list)
    fetched_at: datetime = field(default_factory=_utcnow)
    next_cursor: str | None = None
    error: str | None = None
    rate_limited: bool = False


class Collector(ABC):
    """Base collector interface."""

    source_name: str = ""
    source_type: str = "api"
    trust_level: int = 5  # 1-10, higher = more trusted
    supports_incremental: bool = True

    @abstractmethod
    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        """Fetch advisories since a given timestamp."""
        ...

    @abstractmethod
    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        """Convert raw advisory to normalized format."""
        ...

    def get_health(self) -> dict:
        """Return collector health information."""
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "trust_level": self.trust_level,
            "supports_incremental": self.supports_incremental,
        }
