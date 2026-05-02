import pytest
from app.services.ai_push_service import (
    get_ai_push_candidates,
    build_vuln_push_payload,
    build_rule_based_push,
    format_product_range,
    fmt_dt,
)
from app.db.database import init_db, get_session
from datetime import datetime, timezone


class TestAIPush:
    def test_candidates_excludes_ignored(self):
        init_db("sqlite:///rcon.db")
        session = get_session()
        try:
            candidates = get_ai_push_candidates(session, limit=3, days=365, min_score=0)
            for c in candidates:
                assert c.status != "ignored"
        finally:
            session.close()

    def test_fmt_dt_handles_none(self):
        assert fmt_dt(None) == "未知"

    def test_fmt_dt_handles_naive(self):
        dt = datetime(2026, 5, 1, 10, 0, 0)
        result = fmt_dt(dt)
        assert "2026" in result
        assert "UTC" in result

    def test_format_product_range_fixed(self):
        class AP:
            pass
        ap = AP()
        ap.vendor = "Ubuntu"
        ap.product = "openssl"
        ap.package_ecosystem = ""
        ap.version_start = "1.0.0"
        ap.version_end = "1.0.2"
        ap.fixed_version = "1.0.3"
        result = format_product_range(ap)
        assert "1.0.0" in result
        assert "1.0.3" in result

    def test_build_vuln_push_payload_no_products(self):
        init_db("sqlite:///rcon.db")
        session = get_session()
        try:
            from app.db.models import Vulnerability
            from sqlmodel import select
            v = session.exec(select(Vulnerability).limit(1)).first()
            if v:
                payload = build_vuln_push_payload(session, v)
                assert "key" in payload
                assert isinstance(payload["affected_products"], list)
                assert isinstance(payload["references"], list)
                assert isinstance(payload["source_timeline"], list)
        finally:
            session.close()

    def test_rule_based_push_empty_items(self):
        md = build_rule_based_push([])
        assert "暂无符合条件" in md

    def test_rule_based_push_has_required_sections(self):
        items = [{
            "key": "CVE-2026-0001",
            "title": "Test Vuln",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "epss_percentile": 0.9,
            "is_kev": True,
            "has_poc_signal": False,
            "has_patch": True,
            "action_value_score": 85.0,
            "disclosed_at": "2026-05-01 10:00:00 UTC",
            "disclosed_source": "nvd",
            "published_at": "2026-05-01 10:00:00 UTC",
            "modified_at": "2026-05-01 12:00:00 UTC",
            "description": "A test vulnerability",
            "affected_products": ["TestApp: >= 1.0.0 且 < 2.0.0，修复版本：2.0.1"],
            "source_timeline": [],
            "references": ["https://example.com"],
        }]
        md = build_rule_based_push(items)
        assert "情报发布时间" in md
        assert "影响产品及版本范围" in md
        assert "修复建议" in md
        assert "CVE-2026-0001" in md
