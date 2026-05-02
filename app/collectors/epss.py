import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from loguru import logger
from app.collectors.base import Collector, RawAdvisory, NormalizedVulnerability
from app.utils.http import HTTPClient


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class EPSSCollector(Collector):
    source_name = "epss"
    source_type = "api"
    trust_level = 8
    supports_incremental = True

    def __init__(self, base_url: str = "", cache_dir: str = "data"):
        self.base_url = base_url or "https://api.first.org/data/v1/epss"
        self.http = HTTPClient(rate_per_minute=30)
        self._cache: dict[str, dict] = {}
        self._cache_date: Optional[str] = None
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._load_cache()

    def fetch_since(self, since_time: datetime | None = None) -> list[RawAdvisory]:
        return []

    def normalize(self, raw: RawAdvisory) -> list[NormalizedVulnerability]:
        return []

    def has_today(self, cve_id: str) -> bool:
        self._ensure_fresh_cache()
        return cve_id in self._cache

    def get_today(self, cve_id: str) -> Optional[dict]:
        self._ensure_fresh_cache()
        result = self._cache.get(cve_id)
        return result

    def _cache_path(self) -> Path:
        return self._cache_dir / f"epss_cache_{_today_str()}.json"

    def _ensure_fresh_cache(self):
        today = _today_str()
        if self._cache_date == today:
            return
        # Try loading today's file
        cache_path = self._cache_path()
        if cache_path.exists():
            try:
                with open(cache_path, "r") as f:
                    self._cache = json.load(f)
                self._cache_date = today
                logger.info(f"EPSS cache loaded: {len(self._cache)} entries for {today}")
                return
            except Exception as e:
                logger.warning(f"EPSS cache load failed: {e}")
        self._cache = {}
        self._cache_date = today

    def _save_cache(self):
        try:
            with open(self._cache_path(), "w") as f:
                json.dump(self._cache, f)
            # Remove old cache files (keep last 7 days)
            self._cleanup_old_caches()
        except Exception as e:
            logger.warning(f"EPSS cache save failed: {e}")

    def _load_cache(self):
        cache_path = self._cache_path()
        if cache_path.exists():
            try:
                with open(cache_path, "r") as f:
                    self._cache = json.load(f)
                self._cache_date = _today_str()
                logger.debug(f"EPSS cache: {len(self._cache)} entries loaded")
            except Exception as e:
                logger.debug(f"EPSS cache not available: {e}")
                self._cache = {}
                self._cache_date = _today_str()

    def _cleanup_old_caches(self):
        cutoff = _today_str()
        try:
            d = datetime.strptime(cutoff, "%Y-%m-%d")
            keep_since = (d - timedelta(days=7)).strftime("%Y-%m-%d")
        except ValueError:
            return
        for f in self._cache_dir.glob("epss_cache_*.json"):
            date_part = f.stem.replace("epss_cache_", "")
            if date_part < keep_since:
                try:
                    f.unlink()
                except OSError:
                    pass

    def enrich(self, cve_ids: list[str]) -> dict[str, dict]:
        """Batch query EPSS scores, using cache for today's values."""
        if not cve_ids:
            return {}

        self._ensure_fresh_cache()
        results: dict[str, dict] = {}
        missing: list[str] = []

        for cve in cve_ids:
            cached = self._cache.get(cve)
            if cached:
                results[cve] = cached
            else:
                missing.append(cve)

        if not missing:
            return results

        batch_size = 50
        for i in range(0, len(missing), batch_size):
            batch = missing[i:i + batch_size]
            cve_param = ",".join(batch)
            try:
                resp = self.http.get(
                    self.base_url,
                    params={"cve": cve_param},
                )
                data = resp.json()
            except Exception as e:
                logger.warning(f"EPSS batch {i // batch_size} failed: {e}")
                continue

            for entry in data.get("data", []):
                cve = entry.get("cve", "")
                try:
                    score = {
                        "epss_score": float(entry.get("epss", 0)),
                        "epss_percentile": float(entry.get("percentile", 0)),
                    }
                except (ValueError, TypeError):
                    continue
                self._cache[cve] = score
                results[cve] = score

        self._save_cache()
        logger.info(f"EPSS: enriched {len(results)} CVEs ({len(missing)} fetched, {len(results) - len(missing)} cached)")
        return results
