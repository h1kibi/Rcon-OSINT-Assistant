from app.collectors.nvd import NVDCollector
from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.cisa_rss import CisaRssCollector
from app.collectors.epss import EPSSCollector
from app.collectors.github_advisory import GitHubAdvisoryCollector
from app.collectors.osv import OSVCollector
from app.collectors.msrc import MSRCCollector
from app.collectors.cisco import CiscoCollector
from app.collectors.redhat import RedHatCollector
from app.collectors.ubuntu import UbuntuCollector
from app.collectors.debian import DebianCollector
from app.collectors.cnvd import CNVDCollector
from app.collectors.cnnvd import CNNVDCollector
from app.collectors.cn_vendor import ChineseVendorCollector
from app.pipeline.scorer import ScorerConfig


def build_collectors(cfg):
    c = {}
    epss = EPSSCollector(base_url=cfg.epss.base_url) if cfg.epss.enabled else None

    if cfg.nvd.enabled:
        c["nvd"] = NVDCollector(
            api_key=cfg.nvd.api_key, base_url=cfg.nvd.base_url,
            rate_limit_per_minute=cfg.nvd.rate_limit_per_minute,
            initial_sync_days=cfg.nvd.initial_sync_days,
            max_records=cfg.nvd.max_records,
        )
    if cfg.cisa_kev.enabled:
        c["cisa_kev"] = CisaKevCollector(base_url=cfg.cisa_kev.base_url)
    if cfg.cisa_rss.enabled:
        c["cisa_rss"] = CisaRssCollector(max_records=cfg.cisa_rss.max_records)
    if cfg.github_advisory.enabled:
        c["github_advisory"] = GitHubAdvisoryCollector(token=cfg.github_advisory.token, max_records=1000)
    if cfg.osv.enabled:
        c["osv"] = OSVCollector(base_url=cfg.osv.base_url, max_records=500)
    if cfg.msrc.enabled:
        c["msrc"] = MSRCCollector(api_key=cfg.msrc.api_key, max_records=300)
    if cfg.cisco.enabled:
        c["cisco"] = CiscoCollector(client_id=cfg.cisco.client_id, client_secret=cfg.cisco.client_secret, max_records=300)
    if cfg.redhat.enabled:
        c["redhat"] = RedHatCollector(max_records=300)
    if cfg.ubuntu.enabled:
        c["ubuntu"] = UbuntuCollector(max_records=200)
    if cfg.debian.enabled:
        c["debian"] = DebianCollector(max_records=300)
    if cfg.cnvd.enabled:
        c["cnvd"] = CNVDCollector(max_records=200)
    if cfg.cnnvd.enabled:
        c["cnnvd"] = CNNVDCollector(max_records=200)
    if cfg.cn_vendor.enabled:
        c["cn_vendor"] = ChineseVendorCollector(max_records=200)

    return c, epss


def build_scorer(cfg):
    return ScorerConfig(
        kev_weight=cfg.scoring.kev_weight,
        epss_95_weight=cfg.scoring.epss_95_weight,
        epss_85_weight=cfg.scoring.epss_85_weight,
        cvss_critical_weight=cfg.scoring.cvss_critical_weight,
        cvss_high_weight=cfg.scoring.cvss_high_weight,
        recent_24h_weight=cfg.scoring.recent_24h_weight,
        recent_7d_weight=cfg.scoring.recent_7d_weight,
        official_confirmed_weight=cfg.scoring.official_confirmed_weight,
        patch_available_weight=cfg.scoring.patch_available_weight,
        poc_signal_weight=cfg.scoring.poc_signal_weight,
        multi_source_confirmed_weight=cfg.scoring.multi_source_confirmed_weight,
        watch_keyword_weight=cfg.scoring.watch_keyword_weight,
        watch_keywords=cfg.watch.keywords,
        watch_vendors=cfg.watch.vendors,
        watch_products=cfg.watch.products,
    )
