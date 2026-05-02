import pytest
from datetime import datetime, timezone, timedelta
from app.pipeline.scorer import calculate_score, ScorerConfig, ScoreResult


@pytest.fixture
def config():
    return ScorerConfig(
        watch_keywords=["RCE", "远程代码执行"],
        watch_vendors=["apache"],
        watch_products=["struts"],
    )


@pytest.fixture
def base_vuln():
    return {
        "is_kev": False,
        "epss_percentile": None,
        "cvss_score": None,
        "published_at": datetime.now(timezone.utc) - timedelta(days=30),
        "official_confirmed": False,
        "has_patch": False,
        "has_poc_signal": False,
        "source": "nvd",
        "source_confidence_score": 85.0,
        "title": "Test vuln",
        "description": "A test vulnerability",
    }


class TestScoringKEV:
    def test_kev_hit_adds_35(self, base_vuln, config):
        base_vuln["is_kev"] = True
        result = calculate_score(base_vuln, config)
        assert any("KEV" in r for r in result.reasons)
        assert result.score >= 35
        assert result.severity_band in ("MEDIUM", "HIGH", "CRITICAL", "LOW")

    def test_result_has_severity_band(self, base_vuln, config):
        result = calculate_score(base_vuln, config)
        assert result.severity_band in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_result_has_recommended_action(self, base_vuln, config):
        result = calculate_score(base_vuln, config)
        assert result.recommended_action

    def test_result_has_confidence(self, base_vuln, config):
        result = calculate_score(base_vuln, config)
        assert result.confidence >= 5.0
        assert result.confidence <= 100.0

    def test_penalties_in_penalties_field(self, base_vuln, config):
        base_vuln["source_confidence_score"] = 30
        result = calculate_score(base_vuln, config)
        assert len(result.penalties) > 0
        assert any("低可信" in p for p in result.penalties)


class TestScoringEPSS:
    def test_epss_95_plus_20(self, base_vuln, config):
        base_vuln["epss_percentile"] = 0.97
        result = calculate_score(base_vuln, config)
        assert any("0.95" in r for r in result.reasons)
        assert result.score >= 20

    def test_epss_85_plus_12(self, base_vuln, config):
        base_vuln["epss_percentile"] = 0.90
        result = calculate_score(base_vuln, config)
        assert any("0.85" in r for r in result.reasons)
        assert result.score >= 12

    def test_epss_zero_no_bonus(self, base_vuln, config):
        base_vuln["epss_percentile"] = 0.0
        result = calculate_score(base_vuln, config)
        assert not any("EPSS" in r for r in result.reasons)


class TestScoringCVSS:
    def test_cvss_critical_plus_20(self, base_vuln, config):
        base_vuln["cvss_score"] = 9.8
        result = calculate_score(base_vuln, config)
        assert any("9.0" in r for r in result.reasons)
        assert result.score >= 20

    def test_cvss_high_plus_12(self, base_vuln, config):
        base_vuln["cvss_score"] = 7.5
        result = calculate_score(base_vuln, config)
        assert any("7.0" in r for r in result.reasons)
        assert result.score >= 12

    def test_cvss_zero_no_bonus(self, base_vuln, config):
        base_vuln["cvss_score"] = 0.0
        result = calculate_score(base_vuln, config)
        assert not any("CVSS" in r for r in result.reasons)


class TestScoringRecency:
    def test_24h_ago_plus_12(self, base_vuln, config):
        base_vuln["published_at"] = datetime.now(timezone.utc) - timedelta(hours=6)
        result = calculate_score(base_vuln, config)
        assert any("24h" in r for r in result.reasons)

    def test_7d_ago_plus_8(self, base_vuln, config):
        base_vuln["published_at"] = datetime.now(timezone.utc) - timedelta(days=3)
        result = calculate_score(base_vuln, config)
        assert any("7天" in r for r in result.reasons)


class TestScoringKeywords:
    def test_watch_keyword_in_title(self, base_vuln, config):
        base_vuln["title"] = "Critical RCE in Apache"
        result = calculate_score(base_vuln, config)
        assert any("RCE" in r for r in result.reasons)
        assert result.score >= 15

    def test_watch_vendor_match(self, base_vuln, config):
        base_vuln["affected_products"] = [
            {"vendor": "Apache", "product": "Struts"}
        ]
        result = calculate_score(base_vuln, config)
        assert any("厂商" in r for r in result.reasons)

    def test_watch_product_match(self, base_vuln, config):
        base_vuln["affected_products"] = [
            {"vendor": "Other", "product": "Struts2"}
        ]
        result = calculate_score(base_vuln, config)
        assert any("产品" in r for r in result.reasons)

    def test_vendor_and_product_both_match(self, base_vuln, config):
        base_vuln["affected_products"] = [
            {"vendor": "Apache", "product": "Struts"}
        ]
        result = calculate_score(base_vuln, config)
        assert any("厂商" in r for r in result.reasons)
        assert any("产品" in r for r in result.reasons)


class TestScoringPenalty:
    def test_low_confidence_penalty(self, base_vuln, config):
        base_vuln["source_confidence_score"] = 30
        result = calculate_score(base_vuln, config)
        assert any("低可信" in r for r in result.penalties)

    def test_missing_info_penalty(self, base_vuln, config):
        base_vuln["description"] = ""
        base_vuln["cvss_score"] = None
        base_vuln["published_at"] = None
        result = calculate_score(base_vuln, config)
        assert any("缺失" in r for r in result.penalties)


class TestScoringCap:
    def test_score_capped_at_100(self, base_vuln, config):
        base_vuln["is_kev"] = True
        base_vuln["epss_percentile"] = 0.99
        base_vuln["cvss_score"] = 10.0
        base_vuln["published_at"] = datetime.now(timezone.utc)
        base_vuln["official_confirmed"] = True
        base_vuln["has_patch"] = True
        base_vuln["has_poc_signal"] = True
        base_vuln["source"] = "nvd,cisa_kev"
        base_vuln["title"] = "RCE vulnerability"
        base_vuln["affected_products"] = [{"vendor": "Apache", "product": "Struts"}]
        result = calculate_score(base_vuln, config)
        assert result.score <= 100

    def test_score_floor_at_0(self, base_vuln, config):
        base_vuln["source_confidence_score"] = 10
        base_vuln["description"] = ""
        base_vuln["cvss_score"] = None
        base_vuln["published_at"] = None
        result = calculate_score(base_vuln, config)
        assert result.score >= 0
