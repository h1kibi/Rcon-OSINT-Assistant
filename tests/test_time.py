import pytest
from datetime import datetime, timezone, timedelta
from app.utils.time import utcnow, parse_iso, is_within, format_relative, _ensure_aware


class TestParseIso:
    def test_parse_z_suffix(self):
        dt = parse_iso("2024-01-15T12:00:00Z")
        assert dt is not None
        assert dt.year == 2024

    def test_parse_offset(self):
        dt = parse_iso("2024-01-15T12:00:00+08:00")
        assert dt is not None

    def test_parse_none(self):
        assert parse_iso(None) is None

    def test_parse_empty(self):
        assert parse_iso("") is None

    def test_parse_invalid(self):
        assert parse_iso("not-a-date") is None


class TestEnsureAware:
    def test_naive_becomes_utc(self):
        naive = datetime(2024, 1, 1)
        aware = _ensure_aware(naive)
        assert aware.tzinfo == timezone.utc

    def test_aware_unchanged(self):
        est = timezone(timedelta(hours=-5))
        aware = datetime(2024, 1, 1, tzinfo=est)
        result = _ensure_aware(aware)
        assert result.tzinfo == est


class TestIsWithin:
    def test_recent_is_within(self):
        dt = utcnow() - timedelta(hours=1)
        assert is_within(dt, hours=24) is True

    def test_old_not_within(self):
        dt = utcnow() - timedelta(days=30)
        assert is_within(dt, hours=24) is False

    def test_none_not_within(self):
        assert is_within(None, hours=24) is False

    def test_naive_datetime_no_crash(self):
        naive = datetime(2024, 1, 1)
        # Should not raise TypeError
        result = is_within(naive, hours=24)
        assert isinstance(result, bool)


class TestFormatRelative:
    def test_none(self):
        assert format_relative(None) == "未知"

    def test_just_now(self):
        assert format_relative(utcnow()) == "刚刚"

    def test_minutes(self):
        dt = utcnow() - timedelta(minutes=5)
        assert "分钟前" in format_relative(dt)

    def test_hours(self):
        dt = utcnow() - timedelta(hours=3)
        assert "小时前" in format_relative(dt)

    def test_days(self):
        dt = utcnow() - timedelta(days=5)
        assert "天前" in format_relative(dt)

    def test_naive_datetime_no_crash(self):
        naive = datetime(2020, 1, 1)
        # Should not raise TypeError
        result = format_relative(naive)
        assert "月" in result
