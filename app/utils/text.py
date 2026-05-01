def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text to max_length."""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "…"


def extract_keywords(text: str, keywords: list[str]) -> list[str]:
    """Find which keywords appear in the text (case-insensitive)."""
    if not text or not keywords:
        return []
    lower_text = text.lower()
    return [kw for kw in keywords if kw.lower() in lower_text]
