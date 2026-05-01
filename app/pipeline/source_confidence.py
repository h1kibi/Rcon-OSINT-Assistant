SOURCE_TRUST_MAP = {
    "cisa_kev": 100,
    "nvd": 85,
    "github_advisory": 80,
    "osv": 75,
    "msrc": 90,
    "cisco": 90,
    "redhat": 85,
    "ubuntu": 80,
    "debian": 75,
    "cnvd": 70,
    "cnnvd": 70,
    "epss": 65,
    "poc_metadata": 40,
}


def get_confidence(source_name: str) -> float:
    """Get confidence score for a source. Returns 0-100."""
    return float(SOURCE_TRUST_MAP.get(source_name, 50))


def get_all_confidence_scores() -> dict[str, float]:
    return dict(SOURCE_TRUST_MAP)
