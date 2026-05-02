import time
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import httpx
from loguru import logger
from app.utils.rate_limit import RateLimiter

# Global proxy config
_PROXY_URL: Optional[str] = None
_PROXY_ENABLED: bool = False
_PROXY_DECISIONS: dict[str, bool] = {}

SENSITIVE_QUERY_KEYS = {
    "api_key", "apikey", "access_token", "token",
    "client_secret", "secret", "password", "passwd", "key",
}


def redact_url(url: str) -> str:
    """Redact sensitive credentials and query parameters from URLs."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""

        if parts.username or parts.password:
            netloc = f"***:***@{host}{port}"
        else:
            netloc = f"{host}{port}"

        safe_query_items = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_KEYS:
                safe_query_items.append((key, "***"))
            else:
                safe_query_items.append((key, value))
        safe_query = urlencode(safe_query_items, doseq=True)

        return urlunsplit((parts.scheme, netloc, parts.path, safe_query, ""))
    except Exception:
        return "<redacted-url>"


def set_global_proxy(http_proxy: str = "", https_proxy: str = "", enabled: bool = False):
    """Set global proxy for all HTTP clients."""
    global _PROXY_URL, _PROXY_ENABLED
    if enabled and (http_proxy or https_proxy):
        _PROXY_URL = https_proxy or http_proxy
        _PROXY_ENABLED = True
        logger.info(f"Proxy enabled: {redact_url(_PROXY_URL)}")
        _test_proxy()
    else:
        _PROXY_URL = None
        _PROXY_ENABLED = False
        logger.info("Proxy disabled")


def _test_proxy():
    """Test if proxy is reachable."""
    if not _PROXY_URL:
        return
    try:
        resp = httpx.get("https://httpbin.org/ip", proxy=_PROXY_URL, timeout=5.0)
        if resp.status_code == 200:
            logger.debug("Proxy test OK")
        else:
            logger.warning(f"Proxy test failed: status {resp.status_code}")
    except Exception as e:
        logger.warning(f"Proxy test failed: {e}")


def _should_use_proxy(domain: str) -> bool:
    """Decide whether to use proxy for a domain."""
    if not _PROXY_ENABLED or not _PROXY_URL:
        return False
    if domain in _PROXY_DECISIONS:
        return _PROXY_DECISIONS[domain]

    direct_ok = False
    try:
        resp = httpx.get(f"https://{domain}", timeout=3.0, follow_redirects=True)
        direct_ok = resp.status_code < 500
    except Exception:
        direct_ok = False

    if direct_ok:
        _PROXY_DECISIONS[domain] = False
        return False

    proxy_ok = False
    try:
        resp = httpx.get(f"https://{domain}", proxy=_PROXY_URL, timeout=5.0, follow_redirects=True)
        proxy_ok = resp.status_code < 500
    except Exception:
        proxy_ok = False

    _PROXY_DECISIONS[domain] = proxy_ok
    if proxy_ok:
        logger.info(f"Using proxy for {domain}")
    return proxy_ok


def get_proxy_for_url(url: str) -> Optional[str]:
    """Get proxy URL for a specific request URL if needed."""
    if not _PROXY_ENABLED:
        return None
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if _should_use_proxy(domain):
            return _PROXY_URL
    except Exception:
        pass
    return None


class HTTPClient:
    """httpx wrapper with retry, timeout, rate limiting, and smart proxy."""

    def __init__(
        self,
        rate_per_minute: int = 60,
        timeout: float = 30.0,
        max_retries: int = 3,
        headers: Optional[dict[str, str]] = None,
    ):
        self.rate_limiter = RateLimiter(rate_per_minute)
        self.timeout = timeout
        self.max_retries = max_retries
        self.default_headers = headers or {}
        self._clients: dict[str, httpx.Client] = {}

    def _get_client(self, use_proxy: bool) -> httpx.Client:
        key = "proxy" if use_proxy else "direct"
        if key not in self._clients:
            proxy = _PROXY_URL if use_proxy else None
            self._clients[key] = httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                headers={"User-Agent": "Rcon/0.1", **self.default_headers},
                proxy=proxy,
            )
        return self._clients[key]

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        last_error = None
        use_proxy = get_proxy_for_url(url) is not None
        safe_url = redact_url(url)

        for attempt in range(1, self.max_retries + 1):
            self.rate_limiter.wait()
            try:
                client = self._get_client(use_proxy)
                response = client.request(method, url, **kwargs)
                if response.status_code == 429:
                    try:
                        retry_after = int(response.headers.get("Retry-After", 10))
                    except (ValueError, TypeError):
                        retry_after = 10
                    logger.warning(f"Rate limited on {safe_url}, waiting {retry_after}s")
                    time.sleep(retry_after)
                    continue
                response.raise_for_status()
                return response
            except (httpx.TimeoutException, httpx.ConnectError,
                    httpx.RemoteProtocolError) as e:
                last_error = e
                if not use_proxy and _PROXY_ENABLED:
                    logger.info(f"Direct failed for {safe_url}, trying proxy...")
                    use_proxy = True
                    continue
                wait = 2 ** attempt
                logger.warning(f"Request failed for {safe_url}: {e}, retrying {wait}s (attempt {attempt}/{self.max_retries})")
                time.sleep(wait)

        raise last_error or RuntimeError(f"All retries exhausted for {safe_url}")

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def get_json(self, url: str, **kwargs) -> Any:
        resp = self.get(url, **kwargs)
        return resp.json()

    def close(self):
        for client in self._clients.values():
            client.close()
        self._clients.clear()
