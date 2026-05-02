"""Secure credential storage using OS keychain with config fallback."""

import os
from loguru import logger

_SERVICE = "rcon-osint-assistant"

_KEY_FIELDS = {
    "nvd_api_key": "NVD API Key",
    "github_token": "GitHub Personal Access Token",
    "agent_api_key": "AI Agent API Key",
    "msrc_api_key": "MSRC API Key",
    "cisco_client_id": "Cisco Client ID",
    "cisco_client_secret": "Cisco Client Secret",
}


def _keyring_available() -> bool:
    try:
        import keyring
        return True
    except ImportError:
        return False


def store_secret(key: str, value: str) -> bool:
    """Store a secret in OS keychain. Falls back to env var if keyring unavailable."""
    if not value:
        return False
    if _keyring_available():
        try:
            import keyring
            keyring.set_password(_SERVICE, key, value)
            logger.info(f"Secret stored in keyring: {key}")
            return True
        except Exception as e:
            logger.warning(f"keyring store failed for {key}: {e}")
    return False


def load_secret(key: str, config_value: str = "") -> str:
    """Load a secret: keyring > env var > config value.
    Key fields: nvd_api_key, github_token, agent_api_key, msrc_api_key,
                 cisco_client_id, cisco_client_secret
    """
    if _keyring_available():
        try:
            import keyring
            stored = keyring.get_password(_SERVICE, key)
            if stored:
                return stored
        except Exception as e:
            logger.debug(f"keyring load failed for {key}: {e}")

    # Environment variable fallback
    env_name = f"SECINFO_{key.upper()}"
    if env_name in os.environ:
        return os.environ[env_name]

    return config_value


def migrate_config_to_keyring(config) -> int:
    """Migrate plaintext secrets from config to OS keychain. Returns count of migrated keys."""
    count = 0
    mapping = {
        "nvd_api_key": getattr(config.nvd, "api_key", ""),
        "github_token": getattr(config.github_advisory, "token", ""),
        "agent_api_key": getattr(config.agent, "api_key", "") if hasattr(config, "agent") else "",
        "msrc_api_key": getattr(config.msrc, "api_key", "") if hasattr(config, "msrc") else "",
        "cisco_client_id": getattr(config.cisco, "client_id", "") if hasattr(config, "cisco") else "",
        "cisco_client_secret": getattr(config.cisco, "client_secret", "") if hasattr(config, "cisco") else "",
    }
    for key, value in mapping.items():
        if value and store_secret(key, value):
            count += 1
    return count
