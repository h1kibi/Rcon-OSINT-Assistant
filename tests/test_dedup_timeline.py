import pytest
from datetime import datetime, timezone
from app.collectors.base import NormalizedVulnerability
from app.pipeline.deduplicator import deduplicate


class TestDedupTimeline:
    def test_mixed_naive_aware_datetimes(self):
        naive = datetime(2026, 5, 1, 10, 0, 0)
        aware = datetime(2026, 4, 30, 10, 0, 0, tzinfo=timezone.utc)

        items = [
            NormalizedVulnerability(
                source="nvd",
                primary_key_id="CVE-2026-0001",
                cve_id="CVE-2026-0001",
                title="test",
                description="test",
                published_at=naive,
            ),
            NormalizedVulnerability(
                source="github_advisory",
                primary_key_id="GHSA-test",
                cve_id="CVE-2026-0001",
                title="test",
                description="test",
                published_at=aware,
            ),
        ]

        result = deduplicate(items)

        assert len(result) == 1
        assert result[0].disclosed_at == aware
        assert result[0].disclosed_at.tzinfo is not None
        assert result[0].disclosed_source == "github_advisory"

    def test_single_source_gets_disclosed(self):
        item = NormalizedVulnerability(
            source="nvd",
            primary_key_id="CVE-2026-0001",
            cve_id="CVE-2026-0001",
            title="test",
            description="test",
            published_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        )

        result = deduplicate([item])

        assert len(result) == 1
        assert result[0].disclosed_at == item.published_at
        assert result[0].disclosed_source == "nvd"
