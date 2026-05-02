from datetime import datetime
from loguru import logger
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QAction, QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTableView,
    QLineEdit, QPushButton, QComboBox, QLabel, QCheckBox,
    QHeaderView, QStatusBar, QAbstractItemView,
    QMessageBox, QApplication, QFrame, QMenu, QToolButton,
)
from sqlmodel import Session, select
from app.db import repositories as repo
from app.db.models import AffectedProduct, VulnerabilityReference
from app.ui.models import VulnerabilityTableModel
from app.ui.detail_window import DetailWindow
from app.ui.agent_panel import AgentPanel

# ─── Hacker Dark Theme ─────────────────────────────────────────────
DARK_STYLE = """
QMainWindow, QWidget {
    background: #0d1117; color: #c9d1d9;
    font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QFrame#sidebar {
    background: #161b22; border-right: 1px solid #30363d;
    min-width: 48px; max-width: 48px;
}
QFrame#filterFrame {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px;
}
QLineEdit {
    padding: 6px 10px; border: 1px solid #30363d;
    border-radius: 6px; font-size: 12px;
    background: #0d1117; color: #58a6ff;
    selection-background-color: #1f6feb;
}
QLineEdit:focus { border-color: #58a6ff; }
QLineEdit::placeholder { color: #484f58; }
QPushButton {
    padding: 6px 14px; border: 1px solid #30363d;
    border-radius: 6px; font-size: 12px;
    background: #21262d; color: #c9d1d9;
}
QPushButton:hover { background: #30363d; border-color: #58a6ff; }
QPushButton:pressed { background: #1f6feb; }
QPushButton#primaryBtn {
    background: #238636; color: #ffffff;
    border: 1px solid #2ea043; font-weight: bold;
}
QPushButton#primaryBtn:hover { background: #2ea043; }
QPushButton#accentBtn {
    background: #1f6feb; color: #ffffff;
    border: 1px solid #388bfd;
}
QPushButton#accentBtn:hover { background: #388bfd; }
QToolButton#sidebarBtn {
    background: transparent; border: none;
    border-radius: 8px; padding: 8px;
    color: #8b949e; font-size: 18px;
    min-width: 32px; min-height: 32px;
}
QToolButton#sidebarBtn:hover {
    background: #21262d; color: #c9d1d9;
}
QToolButton#sidebarBtn:checked {
    background: #1f6feb22; color: #58a6ff;
    border-left: 2px solid #58a6ff;
}
QComboBox {
    padding: 5px 8px; border: 1px solid #30363d;
    border-radius: 6px; font-size: 12px;
    background: #21262d; color: #c9d1d9;
    min-width: 70px;
}
QComboBox:hover { border-color: #58a6ff; }
QComboBox::drop-down { border: none; padding-right: 6px; }
QComboBox QAbstractItemView {
    background: #161b22; color: #c9d1d9;
    selection-background-color: #1f6feb;
    border: 1px solid #30363d;
}
QCheckBox { font-size: 12px; spacing: 5px; color: #8b949e; }
QCheckBox::indicator {
    width: 14px; height: 14px;
    border: 1px solid #30363d; border-radius: 3px;
    background: #0d1117;
}
QCheckBox::indicator:checked { background: #238636; border-color: #2ea043; }
QTableView {
    font-size: 12px; gridline-color: #21262d;
    selection-background-color: #1f6feb33;
    selection-color: #58a6ff;
    border: 1px solid #30363d;
    border-radius: 6px; background: #0d1117;
    alternate-background-color: #161b22;
}
QTableView::item { padding: 3px 6px; border: none; }
QTableView::item:selected { background: #1f6feb33; color: #58a6ff; }
QHeaderView::section {
    background: #161b22; padding: 6px 8px;
    border: none; border-bottom: 2px solid #30363d;
    border-right: 1px solid #21262d;
    font-weight: bold; font-size: 11px; color: #58a6ff;
}
QLabel { font-size: 12px; color: #8b949e; }
QStatusBar {
    background: #161b22; border-top: 1px solid #30363d;
    font-size: 11px; color: #484f58;
}
QScrollBar:vertical {
    background: #0d1117; width: 8px; border: none; border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #30363d; border-radius: 4px; min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #484f58; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #0d1117; height: 8px; border: none; border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #30363d; border-radius: 4px; min-width: 30px;
}
QMenu {
    background: #161b22; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 6px; padding: 4px;
}
QMenu::item { padding: 6px 20px; border-radius: 4px; }
QMenu::item:selected { background: #1f6feb; }
QMenu::separator { height: 1px; background: #30363d; margin: 4px 8px; }
"""


class SidebarButton(QToolButton):
    """Custom sidebar button with icon text."""
    def __init__(self, icon_text: str, tooltip: str, parent=None):
        super().__init__(parent)
        self.setText(icon_text)
        self.setToolTip(tooltip)
        self.setObjectName("sidebarBtn")
        self.setCheckable(False)
        self.setFixedSize(40, 40)


class MainWindow(QMainWindow):
    """Main vulnerability intelligence window."""

    refresh_requested = Signal()
    rescore_requested = Signal()
    config_changed = Signal(object)  # Emitted when config is saved, carries new config

    def __init__(self, db_session_factory, config, parent=None):
        super().__init__(parent)
        self.db = db_session_factory
        self.config = config
        self.setWindowTitle("Rcon // 漏洞情报中心")
        self.setMinimumSize(1050, 580)
        self.resize(1250, 680)

        self.setStyleSheet(DARK_STYLE)
        self._detail_windows: list[DetailWindow] = []

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ─── Left Sidebar ─────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(4, 8, 4, 8)
        sidebar_layout.setSpacing(4)

        # Top: View switch buttons (mutually exclusive)
        self.btn_sidebar_home = SidebarButton("🔍", "主页面")
        self.btn_sidebar_home.setCheckable(True)
        self.btn_sidebar_home.setChecked(True)
        self.btn_sidebar_home.clicked.connect(lambda: self._switch_view("home"))
        sidebar_layout.addWidget(self.btn_sidebar_home)

        # Middle: Personal + Agent (mutually exclusive with home)
        self.btn_sidebar_personal = SidebarButton("👤", "个人库 (关注的漏洞)")
        self.btn_sidebar_personal.setCheckable(True)
        self.btn_sidebar_personal.clicked.connect(lambda: self._switch_view("personal"))
        sidebar_layout.addWidget(self.btn_sidebar_personal)

        self.btn_sidebar_agent = SidebarButton("🤖", "Rcon AI 对话")
        self.btn_sidebar_agent.setCheckable(True)
        self.btn_sidebar_agent.clicked.connect(lambda: self._switch_view("agent"))
        sidebar_layout.addWidget(self.btn_sidebar_agent)

        sidebar_layout.addStretch()

        # Bottom: Settings
        self.btn_sidebar_settings = SidebarButton("⚙", "设置")
        self.btn_sidebar_settings.clicked.connect(self._open_settings)
        sidebar_layout.addWidget(self.btn_sidebar_settings)

        self._view_buttons = [self.btn_sidebar_home, self.btn_sidebar_personal, self.btn_sidebar_agent]

        root_layout.addWidget(sidebar)

        # ─── Right Content ────────────────────────────────────────
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(6, 6, 6, 6)
        content_layout.setSpacing(6)

        # ─── Top filter bar ───────────────────────────────────────
        filter_frame = QFrame()
        filter_frame.setObjectName("filterFrame")
        filter_layout = QVBoxLayout(filter_frame)
        filter_layout.setContentsMargins(10, 8, 10, 8)
        filter_layout.setSpacing(5)

        # Row 1: search + quick filters
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索 CVE ID / 关键词...")
        self.search_input.returnPressed.connect(self._on_search)
        row1.addWidget(self.search_input, 1)

        self.btn_search = QPushButton("搜索")
        self.btn_search.setObjectName("primaryBtn")
        self.btn_search.clicked.connect(self._on_search)
        row1.addWidget(self.btn_search)

        row1.addWidget(self._separator())

        self.cb_kev = QCheckBox("KEV")
        self.cb_critical = QCheckBox("严重")
        self.cb_epss_high = QCheckBox("EPSS高")
        self.cb_poc = QCheckBox("PoC")
        self.cb_patch = QCheckBox("有补丁")
        for cb in [self.cb_kev, self.cb_critical, self.cb_epss_high,
                    self.cb_poc, self.cb_patch]:
            cb.stateChanged.connect(self._on_search)
            row1.addWidget(cb)

        row1.addStretch()
        filter_layout.addLayout(row1)

        # Row 2: time, source, status, sort + refresh
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        lbl_time = QLabel("时间:")
        lbl_time.setStyleSheet("color:#58a6ff; font-weight:bold; font-size:11px;")
        row2.addWidget(lbl_time)
        self.cb_time = QComboBox()
        self.cb_time.addItems(["3天", "24小时", "7天", "30天", "全部"])
        self.cb_time.currentIndexChanged.connect(self._on_search)
        row2.addWidget(self.cb_time)

        lbl_status = QLabel("状态:")
        lbl_status.setStyleSheet("color:#58a6ff; font-weight:bold; font-size:11px;")
        row2.addWidget(lbl_status)
        self.cb_status = QComboBox()
        self.cb_status.addItems(["全部", "未读", "已读", "关注", "忽略"])
        self.cb_status.currentIndexChanged.connect(self._on_search)
        row2.addWidget(self.cb_status)

        lbl_source = QLabel("来源:")
        lbl_source.setStyleSheet("color:#58a6ff; font-weight:bold; font-size:11px;")
        row2.addWidget(lbl_source)
        self.cb_source = QComboBox()
        self.cb_source.addItems(["全部", "nvd", "cisa_kev", "github_advisory", "osv", "cisa_rss"])
        self.cb_source.currentIndexChanged.connect(self._on_search)
        row2.addWidget(self.cb_source)

        lbl_sort = QLabel("排序:")
        lbl_sort.setStyleSheet("color:#d29922; font-weight:bold; font-size:11px;")
        row2.addWidget(lbl_sort)
        self.cb_sort = QComboBox()
        self.cb_sort.addItems(["默认", "评分优先", "发布时间优先", "CVSS优先"])
        self.cb_sort.currentIndexChanged.connect(self._on_search)
        row2.addWidget(self.cb_sort)

        row2.addStretch()

        # Refresh button - bigger, on the sort row
        self.btn_quick_refresh = QPushButton("🔄 刷新")
        self.btn_quick_refresh.setToolTip("同步刷新数据")
        self.btn_quick_refresh.setFixedHeight(28)
        self.btn_quick_refresh.setStyleSheet("""
            QPushButton {
                background: #1f6feb; color: white; border: 1px solid #388bfd;
                border-radius: 5px; font-size: 13px; padding: 4px 14px;
                font-weight: bold;
            }
            QPushButton:hover { background: #388bfd; }
            QPushButton:pressed { background: #1158c7; }
        """)
        self.btn_quick_refresh.clicked.connect(self.refresh_requested.emit)
        row2.addWidget(self.btn_quick_refresh)

        filter_layout.addLayout(row2)
        content_layout.addWidget(filter_frame)

        # ─── Table ────────────────────────────────────────────────
        self.table = QTableView()
        self.table_model = VulnerabilityTableModel(self.table)
        self.table.setModel(self.table_model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 130)
        self.table.setColumnWidth(2, 50)
        self.table.setColumnWidth(3, 55)
        self.table.setColumnWidth(4, 55)
        self.table.setColumnWidth(5, 50)
        self.table.setColumnWidth(6, 50)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table.doubleClicked.connect(self._on_row_double_clicked)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        content_layout.addWidget(self.table)

        # ─── Content Stack (main content vs agent) ───────────────
        from PySide6.QtWidgets import QStackedWidget
        self.content_stack = QStackedWidget()
        self.content_stack.addWidget(content)  # index 0: main view

        # Agent Panel (full page replacement)
        self.agent_panel = AgentPanel(config, db_session_factory, self)
        self.content_stack.addWidget(self.agent_panel)  # index 1: agent view

        self.content_stack.setCurrentIndex(0)
        root_layout.addWidget(self.content_stack)

        # ─── Status bar ──────────────────────────────────────────
        self.status_bar = QStatusBar()
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color:#3fb950;")
        self.status_bar.addWidget(self.status_label)
        self.setStatusBar(self.status_bar)

        self._all_data: list[dict] = []
        self._selected_vuln: dict | None = None
        self._personal_mode = False

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def _separator(self):
        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setStyleSheet("color:#30363d;")
        return line

    def load_data(self):
        session = self.db()
        try:
            filters = self._get_filters()
            vulns = repo.get_vulnerabilities(session, **filters)

            vuln_ids = [v.id for v in vulns if v.id]
            all_products = {}
            all_refs = {}
            if vuln_ids:
                prods = session.exec(
                    select(AffectedProduct).where(
                        AffectedProduct.vulnerability_id.in_(vuln_ids)
                    )
                ).all()
                for p in prods:
                    all_products.setdefault(p.vulnerability_id, []).append(p)

                refs_list = session.exec(
                    select(VulnerabilityReference).where(
                        VulnerabilityReference.vulnerability_id.in_(vuln_ids)
                    )
                ).all()
                for r in refs_list:
                    all_refs.setdefault(r.vulnerability_id, []).append(r)

            self._all_data = []
            for v in vulns:
                products = all_products.get(v.id, [])
                refs = all_refs.get(v.id, [])
                self._all_data.append({
                    "id": v.id,
                    "cve_id": v.cve_id,
                    "ghsa_id": v.ghsa_id,
                    "osv_id": v.osv_id,
                    "title": v.title,
                    "description": v.description,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "cvss_vector": v.cvss_vector,
                    "epss_score": v.epss_score,
                    "epss_percentile": v.epss_percentile,
                    "is_kev": v.is_kev,
                    "kev_due_date": v.kev_due_date,
                    "kev_known_ransomware": v.kev_known_ransomware,
                    "official_confirmed": v.official_confirmed,
                    "has_patch": v.has_patch,
                    "has_poc_signal": v.has_poc_signal,
                    "source": v.source,
                    "source_confidence_score": v.source_confidence_score,
                    "action_value_score": v.action_value_score,
                    "action_value_reason": v.action_value_reason,
                    "published_at": str(v.published_at) if v.published_at else None,
                    "modified_at": str(v.modified_at) if v.modified_at else None,
                    "status": v.status,
                    "affected_products": [
                        {"vendor": p.vendor, "product": p.product or p.package_name,
                         "package_ecosystem": p.package_ecosystem,
                         "package_name": p.package_name,
                         "fixed_version": p.fixed_version}
                        for p in products
                    ],
                    "references": [
                        {"url": r.url, "source": r.source, "tags": r.tags}
                        for r in refs
                    ],
                })

            self.table_model.set_data(self._all_data)
            self.status_label.setText(
                f"已加载 {len(self._all_data)} 条漏洞 | {datetime.now().strftime('%H:%M:%S')}"
            )
        except Exception as e:
            self.status_label.setText(f"加载失败: {e}")
            self.status_label.setStyleSheet("color:#f85149;")
        finally:
            session.close()

    def get_unread_count(self, min_score: int = 70) -> int:
        session = self.db()
        try:
            return repo.count_unread_high_value(session, min_score)
        except Exception:
            return 0
        finally:
            session.close()

    def _get_filters(self) -> dict:
        filters = {}

        status_text = self.cb_status.currentText()
        status_map = {"未读": "unread", "已读": "read", "关注": "watched", "忽略": "ignored"}
        if status_text in status_map:
            filters["status"] = status_map[status_text]

        if self.cb_kev.isChecked():
            filters["is_kev"] = True
        if self.cb_critical.isChecked():
            filters["min_cvss"] = 7.0
        if self.cb_epss_high.isChecked():
            filters["min_epss_percentile"] = 0.85
        if self.cb_poc.isChecked():
            filters["has_poc"] = True
        if self.cb_patch.isChecked():
            filters["has_patch"] = True

        time_text = self.cb_time.currentText()
        time_map = {"24小时": 1, "3天": 3, "7天": 7, "30天": 30}
        if time_text in time_map:
            filters["days"] = time_map[time_text]

        source_text = self.cb_source.currentText()
        if source_text != "全部":
            filters["source"] = source_text

        keyword = self.search_input.text().strip()
        if keyword:
            filters["keyword"] = keyword
            # When searching, ignore time filter to show all matching results
            if "days" in filters:
                del filters["days"]

        # Personal mode: show only watched
        if getattr(self, '_personal_mode', False):
            filters["status"] = "watched"

        sort_text = self.cb_sort.currentText()
        sort_map = {
            "默认": "smart",
            "评分优先": "score_desc",
            "发布时间优先": "date_desc",
            "CVSS优先": "cvss_desc",
        }
        filters["sort"] = sort_map.get(sort_text, "smart")

        return filters

    def _on_search(self):
        self.load_data()

    def _open_settings(self):
        from app.ui.settings_dialog import SettingsDialog
        from app.db import repositories as repo

        session = self.db()
        try:
            prefs = repo.get_preferences(session)
            prefs_dict = {
                "refresh_interval_minutes": prefs.refresh_interval_minutes,
                "min_score_to_badge": prefs.min_score_to_badge,
                "min_score_to_notify": prefs.min_score_to_notify,
                "quiet_hours_enabled": prefs.quiet_hours_enabled,
                "quiet_hours_start": prefs.quiet_hours_start,
                "quiet_hours_end": prefs.quiet_hours_end,
                "watch_keywords": prefs.watch_keywords.split(",") if prefs.watch_keywords else [],
            }
        finally:
            session.close()

        dlg = SettingsDialog(self.config, prefs_dict, self)
        if dlg.exec():
            result = dlg.get_result()
            session = self.db()
            try:
                repo.update_preferences(
                    session,
                    refresh_interval_minutes=result.get("refresh_interval_minutes"),
                    min_score_to_badge=result.get("min_score_to_badge"),
                    min_score_to_notify=result.get("min_score_to_notify"),
                    quiet_hours_enabled=result.get("quiet_hours_enabled"),
                    quiet_hours_start=result.get("quiet_hours_start"),
                    quiet_hours_end=result.get("quiet_hours_end"),
                    watch_keywords=",".join(result.get("watch_keywords", [])),
                )
            finally:
                session.close()
            self._save_config_toml(result)
            # Reload config into memory
            self._reload_config()

    def _reload_config(self):
        """Reload config from TOML file into memory."""
        from app.config import load_config
        from pathlib import Path
        config_path = Path("config.toml")
        if config_path.exists():
            self.config = load_config(config_path)
            self.config_changed.emit(self.config)
            logger.info("Config reloaded from disk")

    def _save_config_toml(self, result):
        import tomli_w
        from pathlib import Path

        config_path = Path("config.toml")
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        if config_path.exists():
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        else:
            data = {}

        # Save proxy settings
        if "proxy" not in data:
            data["proxy"] = {}
        data["proxy"]["enabled"] = result.get("proxy_enabled", False)
        data["proxy"]["http_proxy"] = result.get("http_proxy", "")
        data["proxy"]["https_proxy"] = result.get("https_proxy", "")

        if "nvd" not in data:
            data["nvd"] = {}
        data["nvd"]["enabled"] = result.get("nvd_enabled", True)
        if result.get("nvd_api_key"):
            data["nvd"]["api_key"] = result["nvd_api_key"]
        data["nvd"]["rate_limit_per_minute"] = result.get("nvd_rate_limit", 100)
        data["nvd"]["initial_sync_days"] = result.get("nvd_days", 3)
        data["nvd"]["max_records"] = result.get("nvd_max_records", 2000)

        if "cisa_kev" not in data:
            data["cisa_kev"] = {}
        data["cisa_kev"]["enabled"] = result.get("kev_enabled", True)

        if "epss" not in data:
            data["epss"] = {}
        data["epss"]["enabled"] = result.get("epss_enabled", True)

        if "github_advisory" not in data:
            data["github_advisory"] = {}
        data["github_advisory"]["enabled"] = result.get("gh_enabled", True)
        if result.get("gh_token"):
            data["github_advisory"]["token"] = result["gh_token"]

        if "osv" not in data:
            data["osv"] = {}
        data["osv"]["enabled"] = result.get("osv_enabled", True)

        if "scoring" not in data:
            data["scoring"] = {}
        scoring = result.get("scoring", {})
        for key, val in scoring.items():
            data["scoring"][key] = val

        # Save agent settings
        if "agent" not in data:
            data["agent"] = {}
        data["agent"]["enabled"] = result.get("agent_enabled", False)
        data["agent"]["protocol"] = result.get("agent_protocol", "兼容 OpenAI")
        data["agent"]["base_url"] = result.get("agent_base_url", "")
        if result.get("agent_api_key"):
            data["agent"]["api_key"] = result["agent_api_key"]
        data["agent"]["model"] = result.get("agent_model", "")
        data["agent"]["max_tokens"] = result.get("agent_max_tokens", 2000)
        data["agent"]["auto_analysis"] = result.get("agent_auto_analysis", False)
        data["agent"]["db_access"] = result.get("agent_db_access", True)
        if result.get("agent_prompt"):
            data["agent"]["prompt"] = result["agent_prompt"]

        config_path.write_text(tomli_w.dumps(data), encoding="utf-8")

    def _on_row_double_clicked(self, index):
        row = index.row()
        if row < len(self._all_data):
            vuln = self._all_data[row]
            self._open_detail_window(vuln)

    def _open_detail_window(self, vuln: dict):
        win = DetailWindow(vuln, self.config, self)
        win.status_changed.connect(lambda s: self._on_detail_status_changed(vuln, s))
        win.show()
        win.raise_()
        win.activateWindow()
        self._detail_windows.append(win)
        # Update agent panel context
        self.agent_panel.set_current_vuln(vuln)

    def _on_detail_status_changed(self, vuln, new_status):
        """When status changes in detail window, update main table immediately."""
        vuln["status"] = new_status
        self.table_model.set_data(self._all_data)

    def _switch_view(self, view: str):
        """Switch between home, personal, and agent views (mutually exclusive)."""
        active_style = {
            "home": "QToolButton#sidebarBtn { background: #1f6feb22; color: #58a6ff; border-left: 2px solid #58a6ff; }",
            "personal": "QToolButton#sidebarBtn { background: #1f6feb22; color: #d29922; border-left: 2px solid #d29922; }",
            "agent": "QToolButton#sidebarBtn { background: #1f6feb22; color: #58a6ff; border-left: 2px solid #58a6ff; }",
        }

        for btn in self._view_buttons:
            btn.setChecked(False)
            btn.setStyleSheet("")

        if view == "home":
            self.btn_sidebar_home.setChecked(True)
            self.btn_sidebar_home.setStyleSheet(active_style["home"])
            self._personal_mode = False
            self.content_stack.setCurrentIndex(0)
            # Reset filters
            self.search_input.clear()
            self.cb_kev.setChecked(False)
            self.cb_critical.setChecked(False)
            self.cb_epss_high.setChecked(False)
            self.cb_poc.setChecked(False)
            self.cb_patch.setChecked(False)
            self.cb_time.setCurrentIndex(0)
            self.cb_status.setCurrentIndex(0)
            self.cb_source.setCurrentIndex(0)
            self.cb_sort.setCurrentIndex(0)
            self.load_data()

        elif view == "personal":
            self.btn_sidebar_personal.setChecked(True)
            self.btn_sidebar_personal.setStyleSheet(active_style["personal"])
            self._personal_mode = True
            self.content_stack.setCurrentIndex(0)
            self.load_data()

        elif view == "agent":
            self.btn_sidebar_agent.setChecked(True)
            self.btn_sidebar_agent.setStyleSheet(active_style["agent"])
            self._personal_mode = False
            self.content_stack.setCurrentIndex(1)

    def _set_status_by_vuln(self, vuln, status):
        vuln_id = vuln.get("id")
        if vuln_id:
            session = self.db()
            try:
                repo.update_status(session, vuln_id, status)
                vuln["status"] = status
                self.table_model.set_data(self._all_data)
            except Exception as e:
                QMessageBox.warning(self, "错误", f"更新失败: {e}")
            finally:
                session.close()

    def _on_context_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        if row >= len(self._all_data):
            return
        vuln = self._all_data[row]

        menu = QMenu(self)

        detail_action = QAction("查看详情", self)
        detail_action.triggered.connect(lambda: self._open_detail_window(vuln))
        menu.addAction(detail_action)

        menu.addSeparator()

        read_action = QAction("标记已读", self)
        read_action.triggered.connect(lambda: self._set_status(row, "read"))
        menu.addAction(read_action)

        watch_action = QAction("关注", self)
        watch_action.triggered.connect(lambda: self._set_status(row, "watched"))
        menu.addAction(watch_action)

        ignore_action = QAction("忽略", self)
        ignore_action.triggered.connect(lambda: self._set_status(row, "ignored"))
        menu.addAction(ignore_action)

        unread_action = QAction("标记未读", self)
        unread_action.triggered.connect(lambda: self._set_status(row, "unread"))
        menu.addAction(unread_action)

        menu.addSeparator()

        copy_action = QAction("复制 CVE ID", self)
        copy_action.triggered.connect(
            lambda: QApplication.clipboard().setText(vuln.get("cve_id", ""))
        )
        menu.addAction(copy_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _set_status(self, row, status):
        vuln_id = self.table_model.get_vuln_id(row)
        if vuln_id:
            session = self.db()
            try:
                repo.update_status(session, vuln_id, status)
                self._all_data[row]["status"] = status
                self.table_model.set_data(self._all_data)
            except Exception as e:
                QMessageBox.warning(self, "错误", f"更新失败: {e}")
            finally:
                session.close()
