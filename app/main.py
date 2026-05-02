import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from loguru import logger
from PySide6.QtCore import QTimer, Signal, QObject
from PySide6.QtWidgets import QApplication

from app.config import load_config
from app.logging_config import setup_logging
from app.db.database import init_db, get_session
from app.db import repositories as repo
from app.db.models import Vulnerability, AffectedProduct, VulnerabilityReference, SourceRecord, _utcnow
from app.db.migrations import run_migrations
from app.pipeline.scorer import ScorerConfig
from app.pipeline.sync_service import run_sync_service
from app.pipeline.scheduler import SyncScheduler
from app.collectors.nvd import NVDCollector
from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.epss import EPSSCollector
from app.collectors.github_advisory import GitHubAdvisoryCollector
from app.collectors.osv import OSVCollector
from app.collectors.cisa_rss import CisaRssCollector
from app.collectors.msrc import MSRCCollector
from app.collectors.cisco import CiscoCollector
from app.collectors.redhat import RedHatCollector
from app.collectors.ubuntu import UbuntuCollector
from app.collectors.debian import DebianCollector
from app.collectors.cnvd import CNVDCollector
from app.collectors.cnnvd import CNNVDCollector
from app.collectors.cn_vendor import ChineseVendorCollector
from app.ui.floating_ball import RobotOrb
from app.ui.main_window import MainWindow


class SyncSignals(QObject):
    """Signals for cross-thread communication."""
    sync_done = Signal()


def _run_sync_async(settings, collectors, epss_collector, scorer_config, signals):
    """Run sync in background, emit signal when done."""
    def _worker():
        _run_sync(settings, collectors, epss_collector, scorer_config)
        signals.sync_done.emit()
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


def _seed_mock_data(session):
    """Insert mock data for testing when collectors have no data."""
    now = _utcnow()

    mock_vulns = [
        {
            "primary_key_id": "mock:CVE-2024-9999",
            "cve_id": "CVE-2024-9999",
            "title": "GitLab CE/EE 远程代码执行漏洞 (CVE-2024-9999) - Mock",
            "description": (
                "GitLab Community and Enterprise Edition 中存在一个严重的远程代码执行漏洞。"
                "未经认证的攻击者可通过特制请求在目标服务器上执行任意代码。"
                "该漏洞 CVSS 评分 9.8，已被 CISA 列入已知被利用漏洞目录。"
                "EPSS 评分 0.85，处于 97% 百分位，未来 30 天内被利用概率极高。"
                "官方已发布安全补丁，建议立即升级。"
            ),
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.85,
            "epss_percentile": 0.97,
            "is_kev": True,
            "kev_due_date": now + timedelta(days=14),
            "kev_known_ransomware": False,
            "official_confirmed": True,
            "has_patch": True,
            "has_poc_signal": True,
            "source_confidence_score": 95.0,
            "action_value_score": 95,
            "action_value_reason": (
                "KEV命中: +35\n"
                "EPSS分位 0.97 >= 0.95: +20\n"
                "CVSS 9.8 >= 9.0: +20\n"
                "24h内发布: +12\n"
                "官方确认: +10\n"
                "官方补丁可用: +8\n"
                "公开PoC信号: +10\n"
                "命中关注关键词(RCE,远程代码执行): +15\n"
                "综合封顶为100"
            ),
            "published_at": now - timedelta(hours=2),
            "modified_at": now - timedelta(hours=1),
            "source": "nvd,cisa_kev",
            "status": "unread",
        },
        {
            "primary_key_id": "mock:CVE-2024-8888",
            "cve_id": "CVE-2024-8888",
            "title": "Apache Struts2 Remote Code Execution (S2-066) - Mock",
            "description": (
                "Apache Struts2 框架存在远程代码执行漏洞，攻击者可利用文件上传参数绕过"
                "安全限制执行任意命令。CVSS 评分 9.0，影响广泛部署的 Java 企业应用。"
                "官方已确认并发布安全更新。"
            ),
            "severity": "CRITICAL",
            "cvss_score": 9.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.42,
            "epss_percentile": 0.91,
            "is_kev": False,
            "official_confirmed": True,
            "has_patch": True,
            "has_poc_signal": True,
            "source_confidence_score": 90.0,
            "action_value_score": 78,
            "action_value_reason": (
                "EPSS分位 0.91 >= 0.85: +12\n"
                "CVSS 9.0 >= 9.0: +20\n"
                "7天内发布: +8\n"
                "官方确认: +10\n"
                "官方补丁可用: +8\n"
                "公开PoC信号: +10\n"
                "命中关注关键词(RCE,remote code execution): +15\n"
                "综合封顶为100"
            ),
            "published_at": now - timedelta(days=2),
            "modified_at": now - timedelta(hours=12),
            "source": "nvd",
            "status": "unread",
        },
        {
            "primary_key_id": "mock:CVE-2024-7777",
            "cve_id": "CVE-2024-7777",
            "title": "Microsoft Exchange Server Privilege Escalation - Mock",
            "description": (
                "Microsoft Exchange Server 存在权限提升漏洞，已认证的攻击者可利用该漏洞"
                "获取 SYSTEM 权限。CVSS 评分 7.8，CISA 已确认野外利用。"
                "微软已发布安全更新。"
            ),
            "severity": "HIGH",
            "cvss_score": 7.8,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.65,
            "epss_percentile": 0.94,
            "is_kev": True,
            "kev_due_date": now + timedelta(days=21),
            "kev_known_ransomware": True,
            "official_confirmed": True,
            "has_patch": True,
            "has_poc_signal": False,
            "source_confidence_score": 95.0,
            "action_value_score": 85,
            "action_value_reason": (
                "KEV命中: +35\n"
                "EPSS分位 0.94 >= 0.85: +12\n"
                "CVSS 7.8 >= 7.0: +12\n"
                "7天内发布: +8\n"
                "官方确认: +10\n"
                "官方补丁可用: +8\n"
                "命中关注关键词(权限提升,privilege escalation): +15\n"
                "综合封顶为100"
            ),
            "published_at": now - timedelta(days=5),
            "modified_at": now - timedelta(days=1),
            "source": "nvd,cisa_kev",
            "status": "unread",
        },
        {
            "primary_key_id": "mock:CVE-2024-6666",
            "cve_id": "CVE-2024-6666",
            "title": "OpenSSL Denial of Service Vulnerability - Mock",
            "description": (
                "OpenSSL 3.x 存在拒绝服务漏洞，攻击者可发送特制证书导致服务崩溃。"
                "CVSS 评分 5.3，无公开 PoC，官方已有补丁。"
            ),
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "epss_score": 0.05,
            "epss_percentile": 0.30,
            "is_kev": False,
            "official_confirmed": True,
            "has_patch": True,
            "has_poc_signal": False,
            "source_confidence_score": 85.0,
            "action_value_score": 28,
            "action_value_reason": (
                "官方确认: +10\n"
                "官方补丁可用: +8\n"
            ),
            "published_at": now - timedelta(days=14),
            "modified_at": now - timedelta(days=10),
            "source": "nvd",
            "status": "unread",
        },
        {
            "primary_key_id": "mock:CVE-2024-5555",
            "cve_id": "CVE-2024-5555",
            "title": "Linux Kernel Use-After-Free Privilege Escalation - Mock",
            "description": (
                "Linux Kernel 5.15 存在 use-after-free 漏洞，本地攻击者可利用此漏洞"
                "提升权限至 root。CVSS 评分 8.4，已在野外发现利用，CISA 已列入 KEV。"
                "影响所有主流 Linux 发行版。"
            ),
            "severity": "HIGH",
            "cvss_score": 8.4,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            "epss_score": 0.78,
            "epss_percentile": 0.96,
            "is_kev": True,
            "kev_due_date": now + timedelta(days=7),
            "kev_known_ransomware": False,
            "official_confirmed": True,
            "has_patch": True,
            "has_poc_signal": True,
            "source_confidence_score": 95.0,
            "action_value_score": 92,
            "action_value_reason": (
                "KEV命中: +35\n"
                "EPSS分位 0.96 >= 0.95: +20\n"
                "CVSS 8.4 >= 7.0: +12\n"
                "7天内发布: +8\n"
                "官方确认: +10\n"
                "官方补丁可用: +8\n"
                "公开PoC信号: +10\n"
                "命中关注关键词(权限提升): +15\n"
                "综合封顶为100"
            ),
            "published_at": now - timedelta(days=3),
            "modified_at": now - timedelta(hours=6),
            "source": "nvd,cisa_kev",
            "status": "unread",
        },
    ]

    for mv in mock_vulns:
        existing = session.exec(
            __import__("sqlmodel", fromlist=["select"]).select(Vulnerability).where(
                Vulnerability.primary_key_id == mv["primary_key_id"]
            )
        ).first()
        if existing:
            continue

        vuln = Vulnerability(
            primary_key_id=mv["primary_key_id"],
            cve_id=mv["cve_id"],
            title=mv["title"],
            description=mv["description"],
            severity=mv["severity"],
            cvss_score=mv["cvss_score"],
            cvss_vector=mv["cvss_vector"],
            epss_score=mv["epss_score"],
            epss_percentile=mv["epss_percentile"],
            is_kev=mv["is_kev"],
            kev_due_date=mv.get("kev_due_date"),
            kev_known_ransomware=mv.get("kev_known_ransomware", False),
            official_confirmed=mv["official_confirmed"],
            has_patch=mv["has_patch"],
            has_poc_signal=mv["has_poc_signal"],
            source_confidence_score=mv["source_confidence_score"],
            action_value_score=mv["action_value_score"],
            action_value_reason=mv["action_value_reason"],
            published_at=mv["published_at"],
            modified_at=mv["modified_at"],
            first_seen_at=now,
            last_seen_at=now,
            source=mv["source"],
            status=mv["status"],
        )
        session.add(vuln)
    session.commit()
    logger.info(f"Inserted mock data ({len(mock_vulns)} vulnerabilities)")


def main():
    config_path = Path("config.toml")
    if not config_path.exists():
        config_path = Path("config.example.toml")

    settings = load_config(config_path if config_path.exists() else None)

    # Setup logging
    setup_logging(
        level=settings.logging.level,
        log_format=settings.logging.format,
        rotation=settings.logging.rotation,
        retention=settings.logging.retention,
    )
    logger.info("Rcon starting...")

    # Initialize proxy
    from app.utils.http import set_global_proxy
    set_global_proxy(
        http_proxy=settings.proxy.http_proxy,
        https_proxy=settings.proxy.https_proxy,
        enabled=settings.proxy.enabled,
    )

    # Init database
    db_path = settings.app.database_url
    init_db(db_path)
    session = get_session()

    # Run migrations
    try:
        run_migrations(session)
    except Exception as e:
        logger.warning(f"Migrations may have already run: {e}")
    finally:
        session.close()

    # Seed mock data (only in dev mode)
    if "--dev" in sys.argv:
        session = get_session()
        try:
            _seed_mock_data(session)
        except Exception as e:
            logger.warning(f"Mock data seeding: {e}")
        finally:
            session.close()
    else:
        logger.info("Production mode: mock data skipped")

    # PySide6 App
    app = QApplication(sys.argv)
    app.setApplicationName("Rcon")
    app.setQuitOnLastWindowClosed(False)  # Keep running when main window is hidden
    app.setStyle("Fusion")

    # Set application icon
    from PySide6.QtGui import QIcon
    icon_path = Path(__file__).parent / "resources" / "icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Create collectors
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
            c["cisa_rss"] = CisaRssCollector(max_records=200)
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

    collectors, epss_collector = build_collectors(settings)
    scorer_config = build_scorer(settings)

    # Hot-reload refs — must be created BEFORE any function that calls get_settings()
    _settings_ref = [settings]
    _scorer_ref = [scorer_config]
    _collectors_ref = [collectors]
    _epss_ref = [epss_collector]

    def get_settings():
        return _settings_ref[0]

    def get_scorer():
        return _scorer_ref[0]

    def get_collectors():
        return _collectors_ref[0]

    def get_epss():
        return _epss_ref[0]

    # Main window
    main_window = MainWindow(lambda: get_session(), settings)

    # Floating ball
    screen_geo = app.primaryScreen().availableGeometry()
    ball_x = screen_geo.width() - 100
    ball_y = screen_geo.height() // 3
    floating_ball = RobotOrb(
        min_score=settings.ui.min_score_to_badge,
    )
    floating_ball.move(ball_x, ball_y)
    floating_ball.show()

    # Badge timer
    def update_badge():
        count = main_window.get_unread_count(get_settings().ui.min_score_to_badge)
        floating_ball.set_unread_count(count)

    badge_timer = QTimer()
    badge_timer.timeout.connect(update_badge)
    badge_timer.start(15000)

    # Initial data load
    main_window.load_data()
    update_badge()

    # Sync scheduler (runs in background thread)
    sync_signals = SyncSignals()
    sync_signals.sync_done.connect(main_window.load_data)
    sync_signals.sync_done.connect(update_badge)

    sync_lock = threading.Lock()
    sync_pending = [False]

    def run_sync_locked():
        if not sync_lock.acquire(blocking=False):
            sync_pending[0] = True
            logger.info("Sync already running; marked one pending")
            return
        try:
            _run_sync(get_settings(), get_collectors(), get_epss(), get_scorer())
        finally:
            sync_lock.release()
            if sync_pending[0]:
                sync_pending[0] = False
                QTimer.singleShot(200, sync_func)

    def sync_func():
        main_window.load_data()
        update_badge()

        def _worker():
            try:
                run_sync_locked()
            finally:
                sync_signals.sync_done.emit()

        threading.Thread(target=_worker, daemon=True).start()

    def sync_scheduler_recreate():
        return SyncScheduler(
            run_sync_locked,
            interval_minutes=get_settings().app.refresh_interval_minutes,
        )

    sync_scheduler = sync_scheduler_recreate()

    def close_collectors(c, e):
        for v in c.values():
            if hasattr(v, "http"):
                v.http.close()
        if e and hasattr(e, "http"):
            e.http.close()

    def apply_config_change(new_config):
        """Apply config change - caller must hold sync_lock."""
        nonlocal sync_scheduler

        close_collectors(_collectors_ref[0], _epss_ref[0])

        from app.utils.http import set_global_proxy
        set_global_proxy(
            http_proxy=new_config.proxy.http_proxy,
            https_proxy=new_config.proxy.https_proxy,
            enabled=new_config.proxy.enabled,
        )

        _settings_ref[0] = new_config
        _scorer_ref[0] = build_scorer(new_config)
        _collectors_ref[0], _epss_ref[0] = build_collectors(new_config)

        floating_ball._min_score = new_config.ui.min_score_to_badge

        has_sources = bool(get_collectors())
        if not has_sources:
            if sync_scheduler.is_running:
                sync_scheduler.shutdown()
            return

        if sync_scheduler.is_running:
            sync_scheduler.update_interval(new_config.app.refresh_interval_minutes)
        else:
            # Recreate fresh scheduler with new interval
            sync_scheduler = sync_scheduler_recreate()
            sync_scheduler.start(run_immediately=False)
            logger.info("Scheduler recreated and auto-started from config change")

        # Force sync with new collectors
        QTimer.singleShot(1500, sync_func)

    # Pending config for deferred application (sync running → wait)
    _pending_config = [None]

    def on_config_changed(new_config):
        if sync_lock.locked():
            _pending_config[0] = new_config
            logger.info("Sync in progress; config deferred to post-sync")
            return

        if sync_lock.acquire(blocking=False):
            try:
                apply_config_change(new_config)
            finally:
                sync_lock.release()
        else:
            _pending_config[0] = new_config

    # Check pending config after each sync
    def _check_pending():
        cfg = _pending_config[0]
        if cfg is not None:
            _pending_config[0] = None
            on_config_changed(cfg)

    sync_signals.sync_done.connect(_check_pending)

    main_window.config_changed.connect(on_config_changed)

    # Connect signals
    floating_ball.open_main.connect(main_window.show)
    floating_ball.open_main.connect(main_window.raise_)
    floating_ball.open_main.connect(main_window.activateWindow)
    floating_ball.open_main.connect(main_window.load_data)  # Refresh data on open
    floating_ball.quit_app.connect(app.quit)
    floating_ball.toggle_pause.connect(
        lambda: _toggle_pause(floating_ball, sync_scheduler)
    )
    floating_ball.refresh_now.connect(sync_func)
    floating_ball.open_settings.connect(main_window._open_settings)

    main_window.refresh_requested.connect(sync_func)
    main_window.rescore_requested.connect(
        lambda: _rescore_all(get_settings(), get_scorer())
    )

    # Start scheduler if any collectors are enabled
    if get_collectors():
        sync_scheduler.start(run_immediately=False)
        QTimer.singleShot(2000, sync_func)
    else:
        logger.info("No collectors enabled; periodic sync skipped")

    # Show main window
    if not settings.app.start_minimized:
        main_window.show()

    exit_code = app.exec()

    sync_scheduler.shutdown()
    close_collectors(get_collectors(), get_epss())
    sys.exit(exit_code)


def _run_sync(settings, collectors, epss_collector, scorer_config):
    session = get_session()
    try:
        run_sync_service(session, collectors, epss_collector, scorer_config)
        logger.info("Sync completed successfully")
    except Exception as e:
        logger.error(f"Sync failed: {e}")
    finally:
        session.close()


def _rescore_all(settings, scorer_config):
    session = get_session()
    try:
        from sqlmodel import select
        from app.db.models import Vulnerability
        from app.pipeline.scorer import calculate_score

        vulns = session.exec(select(Vulnerability)).all()
        for v in vulns:
            vuln_dict = {
                "is_kev": v.is_kev,
                "epss_percentile": v.epss_percentile,
                "cvss_score": v.cvss_score,
                "published_at": v.published_at,
                "official_confirmed": v.official_confirmed,
                "has_patch": v.has_patch,
                "has_poc_signal": v.has_poc_signal,
                "source": v.source,
                "source_confidence_score": v.source_confidence_score,
                "title": v.title,
                "description": v.description,
            }
            score, reasons = calculate_score(vuln_dict, scorer_config)
            v.action_value_score = score
            v.action_value_reason = "\n".join(reasons)
            session.add(v)
        session.commit()
        logger.info(f"Rescored {len(vulns)} vulnerabilities")
    except Exception as e:
        logger.error(f"Rescore failed: {e}")
    finally:
        session.close()


def _toggle_pause(ball, scheduler):
    if scheduler.is_paused:
        scheduler.resume()
        ball.set_paused(False)
    else:
        scheduler.pause()
        ball.set_paused(True)


