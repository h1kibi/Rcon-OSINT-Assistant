import os
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseModel):
    refresh_interval_minutes: int = 60
    database_url: str = "sqlite:///data/rcon.db"
    start_minimized: bool = False
    auto_update_on_startup: bool = False
    auto_update_enabled: bool = False
    update_on_ai_push_startup: bool = False


class ProxyConfig(BaseModel):
    enabled: bool = False
    http_proxy: str = ""
    https_proxy: str = ""


class UIConfig(BaseModel):
    floating_ball_opacity: float = 0.85
    min_score_to_badge: int = 70
    min_score_to_notify: int = 80
    quiet_hours_enabled: bool = True
    quiet_hours_start: str = "23:00"
    quiet_hours_end: str = "08:00"


class NVDConfig(BaseModel):
    enabled: bool = True
    api_key: str = ""
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    rate_limit_per_minute: int = 20
    initial_sync_days: int = 3
    max_records: int = 2000


class CisaKevConfig(BaseModel):
    enabled: bool = True
    base_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )


class EPSSConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://api.first.org/data/v1/epss"


class GitHubAdvisoryConfig(BaseModel):
    enabled: bool = True
    token: str = ""


class OSVConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://api.osv.dev/v1"


class MSRCConfig(BaseModel):
    enabled: bool = False
    api_key: str = ""


class CiscoConfig(BaseModel):
    enabled: bool = False
    client_id: str = ""
    client_secret: str = ""


class RedHatConfig(BaseModel):
    enabled: bool = False


class UbuntuConfig(BaseModel):
    enabled: bool = False


class DebianConfig(BaseModel):
    enabled: bool = False


class CNVDConfig(BaseModel):
    enabled: bool = False


class CNNVDConfig(BaseModel):
    enabled: bool = False


class CNVendorConfig(BaseModel):
    enabled: bool = True


class ScoringConfig(BaseModel):
    kev_weight: int = 35
    epss_95_weight: int = 20
    epss_85_weight: int = 12
    cvss_critical_weight: int = 20
    cvss_high_weight: int = 12
    recent_24h_weight: int = 12
    recent_7d_weight: int = 8
    official_confirmed_weight: int = 10
    patch_available_weight: int = 8
    poc_signal_weight: int = 10
    multi_source_confirmed_weight: int = 8
    watch_keyword_weight: int = 15


class WatchConfig(BaseModel):
    keywords: list[str] = Field(default_factory=lambda: ["RCE", "远程代码执行", "auth bypass", "权限提升", "命令执行"])
    vendors: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}"
    rotation: str = "10 MB"
    retention: str = "7 days"


class AgentConfig(BaseModel):
    enabled: bool = False
    protocol: str = "兼容 OpenAI"
    api_key: str = ""
    model: str = "gpt-4o"
    base_url: str = "https://api.openai.com/v1"
    max_tokens: int = 2000
    auto_analysis: bool = False
    db_access: bool = True
    prompt: str = (
        "你是一个专业的网络安全漏洞分析专家。请根据提供的漏洞信息，从以下维度进行分析：\n"
        "1. 漏洞危害性评估\n2. 影响范围分析\n3. 利用难度评估\n"
        "4. 修复建议\n5. 防御措施建议"
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECINFO_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    app: AppConfig = Field(default_factory=AppConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    nvd: NVDConfig = Field(default_factory=NVDConfig)
    cisa_kev: CisaKevConfig = Field(default_factory=CisaKevConfig)
    epss: EPSSConfig = Field(default_factory=EPSSConfig)
    github_advisory: GitHubAdvisoryConfig = Field(default_factory=GitHubAdvisoryConfig)
    osv: OSVConfig = Field(default_factory=OSVConfig)
    msrc: MSRCConfig = Field(default_factory=MSRCConfig)
    cisco: CiscoConfig = Field(default_factory=CiscoConfig)
    redhat: RedHatConfig = Field(default_factory=RedHatConfig)
    ubuntu: UbuntuConfig = Field(default_factory=UbuntuConfig)
    debian: DebianConfig = Field(default_factory=DebianConfig)
    cnvd: CNVDConfig = Field(default_factory=CNVDConfig)
    cnnvd: CNNVDConfig = Field(default_factory=CNNVDConfig)
    cn_vendor: CNVendorConfig = Field(default_factory=CNVendorConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    watch: WatchConfig = Field(default_factory=WatchConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)


_CONFIG_MODELS = {
    "app": AppConfig,
    "proxy": ProxyConfig,
    "ui": UIConfig,
    "nvd": NVDConfig,
    "cisa_kev": CisaKevConfig,
    "epss": EPSSConfig,
    "github_advisory": GitHubAdvisoryConfig,
    "osv": OSVConfig,
    "msrc": MSRCConfig,
    "cisco": CiscoConfig,
    "redhat": RedHatConfig,
    "ubuntu": UbuntuConfig,
    "debian": DebianConfig,
    "cnvd": CNVDConfig,
    "cnnvd": CNNVDConfig,
    "cn_vendor": CNVendorConfig,
    "scoring": ScoringConfig,
    "watch": WatchConfig,
    "logging": LoggingConfig,
    "agent": AgentConfig,
}


import json
from pydantic import TypeAdapter


def _parse_env_value(raw: str, annotation) -> Any:
    """Parse env var string to the target pydantic type."""
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        decoded = raw
    return TypeAdapter(annotation).validate_python(decoded)


def _collect_env_overrides(section_name: str, model_cls: type[BaseModel]) -> dict[str, Any]:
    """Collect only env vars that are actually present for a config section."""
    prefix = f"SECINFO_{section_name.upper()}__"
    overrides: dict[str, Any] = {}
    for field_name, field_info in model_cls.model_fields.items():
        env_name = f"{prefix}{field_name.upper()}"
        if env_name in os.environ:
            overrides[field_name] = _parse_env_value(
                os.environ[env_name], field_info.annotation
            )
    return overrides


def load_config(config_path: Optional[Path] = None) -> Settings:
    """Load configuration from TOML file (base), env vars (override).

    Priority: env var > TOML > model default
    Each section is independent: TOML provides base values,
    and only explicitly set env vars override them.
    """
    settings = Settings()

    # Find first available config file
    if config_path is None:
        candidates = [Path("config.toml"), Path("config.example.toml")]
    else:
        candidates = [config_path]

    config_data: dict[str, Any] = {}
    for path in candidates:
        if path.exists():
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib
            config_data = tomllib.loads(path.read_text(encoding="utf-8"))
            break

    # Merge per section: TOML base + env overrides
    for section_name, model_cls in _CONFIG_MODELS.items():
        base = config_data.get(section_name, {})
        env_overrides = _collect_env_overrides(section_name, model_cls)
        merged = {**base, **env_overrides}
        setattr(settings, section_name, model_cls(**merged))

    return settings
