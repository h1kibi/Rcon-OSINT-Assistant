import pytest
from pathlib import Path
from app.config import load_config


class TestLoadConfig:
    def test_reads_toml_file(self, tmp_path, monkeypatch):
        p = tmp_path / "config.toml"
        p.write_text("[nvd]\nrate_limit_per_minute = 100\n", encoding="utf-8")
        monkeypatch.delenv("SECINFO_NVD__RATE_LIMIT_PER_MINUTE", raising=False)

        settings = load_config(p)
        assert settings.nvd.rate_limit_per_minute == 100

    def test_env_overrides_toml(self, tmp_path, monkeypatch):
        p = tmp_path / "config.toml"
        p.write_text("[nvd]\nrate_limit_per_minute = 100\n", encoding="utf-8")
        monkeypatch.setenv("SECINFO_NVD__RATE_LIMIT_PER_MINUTE", "200")

        settings = load_config(p)
        assert settings.nvd.rate_limit_per_minute == 200

    def test_defaults_do_not_override_toml(self, tmp_path, monkeypatch):
        p = tmp_path / "config.toml"
        p.write_text("[app]\nrefresh_interval_minutes = 5\n", encoding="utf-8")
        monkeypatch.delenv("SECINFO_APP__REFRESH_INTERVAL_MINUTES", raising=False)

        settings = load_config(p)
        assert settings.app.refresh_interval_minutes == 5

    def test_falls_back_to_example(self, tmp_path, monkeypatch):
        ex = tmp_path / "config.example.toml"
        ex.write_text("[nvd]\nmax_records = 50\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("SECINFO_NVD__MAX_RECORDS", raising=False)

        settings = load_config()
        assert settings.nvd.max_records == 50

    def test_empty_config_uses_defaults(self, tmp_path):
        p = tmp_path / "config.toml"
        p.write_text("", encoding="utf-8")

        settings = load_config(p)
        assert settings.nvd.enabled is True
        assert settings.nvd.rate_limit_per_minute == 20
