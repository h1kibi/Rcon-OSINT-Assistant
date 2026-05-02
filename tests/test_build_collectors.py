import pytest
import threading
from unittest.mock import MagicMock, patch
from app.config import Settings, AppConfig, NVDConfig, CisaKevConfig, CisaRssConfig
from app.collectors.builder import build_collectors, build_scorer


class TestBuildCollectors:
    def test_disabled_nvd_excluded(self):
        cfg = Settings()
        cfg.nvd.enabled = False
        c, _ = build_collectors(cfg)
        assert "nvd" not in c

    def test_disabled_cisa_kev_excluded(self):
        cfg = Settings()
        cfg.cisa_kev.enabled = False
        c, _ = build_collectors(cfg)
        assert "cisa_kev" not in c

    def test_disabled_cisa_rss_excluded(self):
        cfg = Settings()
        cfg.cisa_rss.enabled = False
        c, _ = build_collectors(cfg)
        assert "cisa_rss" not in c

    def test_disabled_kev_does_not_include_rss(self):
        """CISA KEV disabled should NOT hide CISA RSS — they are independent."""
        cfg = Settings()
        cfg.cisa_kev.enabled = False
        cfg.cisa_rss.enabled = True
        c, _ = build_collectors(cfg)
        assert "cisa_kev" not in c
        assert "cisa_rss" in c

    def test_disabled_rss_keeps_kev(self):
        """CISA RSS disabled should NOT hide CISA KEV."""
        cfg = Settings()
        cfg.cisa_kev.enabled = True
        cfg.cisa_rss.enabled = False
        c, _ = build_collectors(cfg)
        assert "cisa_kev" in c
        assert "cisa_rss" not in c

    def test_disabled_epss_returns_none(self):
        cfg = Settings()
        cfg.epss.enabled = False
        _, epss = build_collectors(cfg)
        assert epss is None

    def test_enabled_epss_returns_collector(self):
        cfg = Settings()
        cfg.epss.enabled = True
        _, epss = build_collectors(cfg)
        assert epss is not None

    def test_enabled_nvd_included(self):
        cfg = Settings()
        cfg.nvd.enabled = True
        c, _ = build_collectors(cfg)
        assert "nvd" in c

    def test_all_disabled_returns_empty(self):
        cfg = Settings()
        for attr in ["nvd", "cisa_kev", "cisa_rss", "github_advisory", "osv",
                      "msrc", "cisco", "redhat", "ubuntu", "debian",
                      "cnvd", "cnnvd", "cn_vendor", "epss"]:
            getattr(cfg, attr).enabled = False
        c, epss = build_collectors(cfg)
        assert c == {}
        assert epss is None
