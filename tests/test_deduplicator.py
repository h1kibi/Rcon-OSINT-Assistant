import pytest
from app.collectors.base import NormalizedVulnerability
from app.pipeline.deduplicator import deduplicate


def make_vuln(primary_key_id, cve_id=None, source="nvd", confidence=85.0, **kwargs):
    return NormalizedVulnerability(
        primary_key_id=primary_key_id,
        cve_id=cve_id,
        source=source,
        source_confidence_score=confidence,
        **kwargs,
    )


class TestDeduplication:
    def test_single_vuln_unchanged(self):
        vulns = [make_vuln("nvd:CVE-2024-0001", cve_id="CVE-2024-0001")]
        result = deduplicate(vulns)
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2024-0001"

    def test_same_cve_merged(self):
        vulns = [
            make_vuln("nvd:CVE-2024-0001", cve_id="CVE-2024-0001", title="Title from NVD"),
            make_vuln("kev:CVE-2024-0001", cve_id="CVE-2024-0001", is_kev=True),
        ]
        result = deduplicate(vulns)
        assert len(result) == 1
        assert result[0].is_kev is True
        assert result[0].title == "Title from NVD"

    def test_different_cves_not_merged(self):
        vulns = [
            make_vuln("nvd:CVE-2024-0001", cve_id="CVE-2024-0001"),
            make_vuln("nvd:CVE-2024-0002", cve_id="CVE-2024-0002"),
        ]
        result = deduplicate(vulns)
        assert len(result) == 2

    def test_higher_confidence_source_wins(self):
        vulns = [
            make_vuln("nvd:CVE-2024-0001", cve_id="CVE-2024-0001",
                      severity="MEDIUM", confidence=85),
            make_vuln("kev:CVE-2024-0001", cve_id="CVE-2024-0001",
                      severity="HIGH", confidence=100),
        ]
        result = deduplicate(vulns)
        assert len(result) == 1
        assert result[0].severity == "HIGH"

    def test_kev_flag_preserved(self):
        vulns = [
            make_vuln("nvd:CVE-2024-0001", cve_id="CVE-2024-0001", is_kev=False),
            make_vuln("kev:CVE-2024-0001", cve_id="CVE-2024-0001", is_kev=True),
        ]
        result = deduplicate(vulns)
        assert result[0].is_kev is True

    def test_references_merged(self):
        vulns = [
            make_vuln("nvd:CVE-2024-0001", cve_id="CVE-2024-0001",
                      references=[{"url": "https://a.com", "source": "nvd"}]),
            make_vuln("kev:CVE-2024-0001", cve_id="CVE-2024-0001",
                      references=[{"url": "https://b.com", "source": "kev"}]),
        ]
        result = deduplicate(vulns)
        urls = {r["url"] for r in result[0].references}
        assert urls == {"https://a.com", "https://b.com"}

    def test_source_combined(self):
        vulns = [
            make_vuln("nvd:CVE-2024-0001", cve_id="CVE-2024-0001", source="nvd"),
            make_vuln("kev:CVE-2024-0001", cve_id="CVE-2024-0001", source="cisa_kev"),
        ]
        result = deduplicate(vulns)
        assert "nvd" in result[0].source
        assert "cisa_kev" in result[0].source

    def test_ghsa_id_used_as_fallback_key(self):
        vulns = [
            make_vuln("ghsa:GHSA-xxxx", ghsa_id="GHSA-xxxx", title="GHSA vuln"),
        ]
        result = deduplicate(vulns)
        assert len(result) == 1
        assert result[0].ghsa_id == "GHSA-xxxx"

    def test_empty_input(self):
        result = deduplicate([])
        assert result == []
