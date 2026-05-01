from datetime import datetime, timezone, timedelta


def utcnow() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware. Naive datetimes are assumed UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def hours_ago(n: int) -> datetime:
    """Return datetime n hours ago."""
    return utcnow() - timedelta(hours=n)


def days_ago(n: int) -> datetime:
    """Return datetime n days ago."""
    return utcnow() - timedelta(days=n)


def parse_iso(iso_str: str | None) -> datetime | None:
    """Parse ISO 8601 string to datetime. Supports Z suffix."""
    if not iso_str:
        return None
    s = iso_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def is_within(dt: datetime | None, hours: int = 24) -> bool:
    """Check if dt is within the last N hours."""
    if dt is None:
        return False
    dt = _ensure_aware(dt)
    return dt >= hours_ago(hours)


def format_relative(dt: datetime | None) -> str:
    """Return human-readable relative time string."""
    if dt is None:
        return "未知"
    now = utcnow()
    dt = _ensure_aware(dt)
    diff = now - dt
    if diff.total_seconds() < 0:
        return "刚刚"
    minutes = diff.total_seconds() // 60
    if minutes < 1:
        return "刚刚"
    if minutes < 60:
        return f"{int(minutes)}分钟前"
    hours = minutes // 60
    if hours < 24:
        return f"{int(hours)}小时前"
    days = hours // 24
    if days < 30:
        return f"{int(days)}天前"
    months = days // 30
    return f"{int(months)}个月前"
