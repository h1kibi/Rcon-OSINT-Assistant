from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QColor, QPen
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QSpinBox, QCheckBox, QPushButton, QGroupBox, QFormLayout,
    QComboBox, QTabWidget, QWidget, QScrollArea, QFrame, QTextEdit,
)

SETTINGS_STYLE = """
QDialog {
    background: #0d1117; color: #c9d1d9;
    font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QTabWidget::pane {
    border: 1px solid #30363d; border-radius: 6px;
    background: #0d1117;
}
QTabBar::tab {
    background: #161b22; color: #8b949e;
    border: 1px solid #30363d; border-bottom: none;
    padding: 8px 16px; margin-right: 2px;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
    font-size: 13px;
}
QTabBar::tab:selected {
    background: #0d1117; color: #58a6ff; border-bottom: 2px solid #58a6ff;
}
QTabBar::tab:hover { color: #c9d1d9; }
QGroupBox {
    font-weight: bold; border: 1px solid #30363d;
    border-radius: 6px; margin-top: 12px; padding: 18px 12px 12px 12px;
    color: #58a6ff; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
QLabel { color: #8b949e; font-size: 12px; }
QLineEdit {
    padding: 7px 10px; border: 1px solid #30363d;
    border-radius: 4px; background: #161b22; color: #c9d1d9;
    font-size: 13px; min-height: 22px;
}
QLineEdit:focus { border-color: #58a6ff; }
QSpinBox {
    padding: 7px 10px; border: 1px solid #30363d;
    border-radius: 4px; background: #161b22; color: #c9d1d9;
    font-size: 13px; min-height: 22px;
}
QSpinBox:focus { border-color: #58a6ff; }
QComboBox {
    padding: 7px 10px; border: 1px solid #30363d;
    border-radius: 4px; background: #161b22; color: #c9d1d9;
    font-size: 13px; min-height: 22px;
}
QComboBox:focus { border-color: #58a6ff; }
QComboBox QAbstractItemView {
    background: #161b22; color: #c9d1d9;
    selection-background-color: #1f6feb;
}
QCheckBox { color: #c9d1d9; font-size: 13px; spacing: 6px; }
QPushButton {
    padding: 7px 18px; border: 1px solid #30363d;
    border-radius: 6px; font-size: 13px;
    background: #21262d; color: #c9d1d9;
}
QPushButton:hover { background: #30363d; border-color: #58a6ff; }
QPushButton#saveBtn {
    background: #1f6feb; color: white; border-color: #388bfd;
    font-weight: bold;
}
QPushButton#saveBtn:hover { background: #388bfd; }
QScrollArea { border: none; background: #0d1117; }
QScrollBar:vertical {
    background: #0d1117; width: 8px; border: none; border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #30363d; border-radius: 4px; min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #484f58; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


class NoScrollSpinBox(QSpinBox):
    def wheelEvent(self, event):
        event.ignore()


class NoScrollComboBox(QComboBox):
    def wheelEvent(self, event):
        event.ignore()


class GlowCheckBox(QCheckBox):
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        size = 18
        y = (self.height() - size) // 2
        rect = self.rect().adjusted(2, y, -(self.width() - size - 2), -y)

        if self.isChecked():
            painter.setBrush(QColor("#58a6ff"))
            painter.setPen(QPen(QColor("#58a6ff"), 2))
            painter.drawRoundedRect(rect, 4, 4)
            painter.setPen(QPen(QColor("#ffffff"), 2.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            cx, cy = rect.center().x(), rect.center().y()
            painter.drawLine(int(cx - 4), int(cy), int(cx - 1), int(cy + 3))
            painter.drawLine(int(cx - 1), int(cy + 3), int(cx + 5), int(cy - 3))
        else:
            painter.setBrush(QColor("#0d1117"))
            painter.setPen(QPen(QColor("#484f58"), 2))
            painter.drawRoundedRect(rect, 4, 4)
        painter.end()

        if self.text():
            p = QPainter(self)
            p.setPen(QColor("#c9d1d9"))
            p.setFont(self.font())
            p.drawText(
                rect.right() + 8, 0,
                self.width() - rect.width() - 8, self.height(),
                Qt.AlignVCenter | Qt.AlignLeft, self.text()
            )
            p.end()


def _form_row(label, widget):
    """Create a QFormLayout row with consistent style."""
    form = QFormLayout()
    form.setVerticalSpacing(0)
    form.setContentsMargins(0, 0, 0, 0)
    form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
    form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
    form.addRow(label, widget)
    return form


class SettingsDialog(QDialog):
    def __init__(self, config, preferences: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.setMinimumSize(500, 550)
        self.resize(520, 600)
        self.setStyleSheet(SETTINGS_STYLE)
        self.config = config

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(12, 12, 12, 12)

        tabs = QTabWidget()
        tabs.addTab(self._build_general_tab(preferences), "通用设置")
        tabs.addTab(self._build_sources_tab(), "情报来源")
        tabs.addTab(self._build_scoring_tab(), "评分配置")
        tabs.addTab(self._build_agent_tab(), "Agent 配置")
        layout.addWidget(tabs)

        btn_layout = QHBoxLayout()
        btn_save = QPushButton("保存")
        btn_save.setObjectName("saveBtn")
        btn_save.setFixedHeight(34)
        btn_save.clicked.connect(self._on_save)
        btn_cancel = QPushButton("取消")
        btn_cancel.setFixedHeight(34)
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_cancel)
        btn_layout.addWidget(btn_save)
        layout.addLayout(btn_layout)

    def _build_general_tab(self, prefs):
        """General settings with scroll area."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(14)

        # ── 数据同步 ──
        g1 = QGroupBox("数据同步")
        l1 = QVBoxLayout()
        l1.setSpacing(10)
        self.refresh_interval = NoScrollSpinBox()
        self.refresh_interval.setRange(5, 1440)
        self.refresh_interval.setValue(prefs.get("refresh_interval_minutes", 15))
        self.refresh_interval.setSuffix(" 分钟")
        self.refresh_interval.setFixedHeight(34)
        l1.addLayout(_form_row("同步间隔:", self.refresh_interval))
        g1.setLayout(l1)
        layout.addWidget(g1)

        # ── 联网行为 ──
        g_net = QGroupBox("联网行为")
        l_net = QVBoxLayout()
        l_net.setSpacing(10)
        self.chk_auto_update_startup = GlowCheckBox("启动时自动联网更新数据库")
        self.chk_auto_update_startup.setToolTip("打开程序后自动从互联网拉取最新漏洞情报")
        self.chk_auto_update_startup.setChecked(getattr(self.config.app, "auto_update_on_startup", False))
        l_net.addWidget(self.chk_auto_update_startup)
        self.chk_auto_update_enabled = GlowCheckBox("启用后台定时联网更新")
        self.chk_auto_update_enabled.setToolTip("按设置的刷新间隔定时更新本地数据库")
        self.chk_auto_update_enabled.setChecked(getattr(self.config.app, "auto_update_enabled", False))
        l_net.addWidget(self.chk_auto_update_enabled)
        self.chk_update_ai_push_startup = GlowCheckBox("启动后 AI 推送前先联网更新")
        self.chk_update_ai_push_startup.setToolTip("启动后生成 AI 推送前，先执行一次数据库更新")
        self.chk_update_ai_push_startup.setChecked(getattr(self.config.app, "update_on_ai_push_startup", False))
        l_net.addWidget(self.chk_update_ai_push_startup)
        g_net.setLayout(l_net)
        layout.addWidget(g_net)

        # ── 网络代理 ──
        g2 = QGroupBox("网络代理")
        l2 = QVBoxLayout()
        l2.setSpacing(10)
        self.proxy_enabled = GlowCheckBox("启用代理")
        self.proxy_enabled.setChecked(self.config.proxy.enabled)
        l2.addWidget(self.proxy_enabled)
        self.http_proxy = QLineEdit()
        self.http_proxy.setText(self.config.proxy.http_proxy)
        self.http_proxy.setPlaceholderText("http://127.0.0.1:7890")
        self.http_proxy.setFixedHeight(34)
        l2.addLayout(_form_row("HTTP 代理:", self.http_proxy))
        self.https_proxy = QLineEdit()
        self.https_proxy.setText(self.config.proxy.https_proxy)
        self.https_proxy.setPlaceholderText("http://127.0.0.1:7890 或 socks5://127.0.0.1:7890")
        self.https_proxy.setFixedHeight(34)
        l2.addLayout(_form_row("HTTPS 代理:", self.https_proxy))
        g2.setLayout(l2)
        layout.addWidget(g2)

        # ── 提醒设置 ──
        g3 = QGroupBox("提醒设置")
        l3 = QVBoxLayout()
        l3.setSpacing(10)
        self.min_badge = NoScrollSpinBox()
        self.min_badge.setRange(0, 100)
        self.min_badge.setValue(prefs.get("min_score_to_badge", 70))
        self.min_badge.setPrefix("≥ ")
        self.min_badge.setFixedHeight(34)
        l3.addLayout(_form_row("红点最低分:", self.min_badge))
        self.min_notify = NoScrollSpinBox()
        self.min_notify.setRange(0, 100)
        self.min_notify.setValue(prefs.get("min_score_to_notify", 80))
        self.min_notify.setPrefix("≥ ")
        self.min_notify.setFixedHeight(34)
        l3.addLayout(_form_row("通知最低分:", self.min_notify))
        self.quiet_enabled = GlowCheckBox("启用安静时间段")
        self.quiet_enabled.setChecked(prefs.get("quiet_hours_enabled", True))
        l3.addWidget(self.quiet_enabled)
        quiet_hbox = QHBoxLayout()
        quiet_hbox.setSpacing(8)
        self.quiet_start = NoScrollComboBox()
        self.quiet_start.addItems([f"{h:02d}:00" for h in range(24)])
        self.quiet_start.setCurrentText(prefs.get("quiet_hours_start", "23:00"))
        self.quiet_start.setFixedHeight(34)
        self.quiet_end = NoScrollComboBox()
        self.quiet_end.addItems([f"{h:02d}:00" for h in range(24)])
        self.quiet_end.setCurrentText(prefs.get("quiet_hours_end", "08:00"))
        self.quiet_end.setFixedHeight(34)
        quiet_hbox.addWidget(self.quiet_start)
        quiet_hbox.addWidget(QLabel("~"))
        quiet_hbox.addWidget(self.quiet_end)
        l3.addLayout(_form_row("安静时段:", quiet_hbox))
        g3.setLayout(l3)
        layout.addWidget(g3)

        # ── 关注关键词 ──
        g4 = QGroupBox("关注关键词")
        l4 = QVBoxLayout()
        self.keywords = QLineEdit()
        kw_str = prefs.get("watch_keywords", "")
        if isinstance(kw_str, list):
            kw_str = ",".join(kw_str)
        self.keywords.setText(kw_str)
        self.keywords.setPlaceholderText("多个关键词用逗号分隔, 如: RCE,权限提升,0day")
        self.keywords.setFixedHeight(34)
        l4.addWidget(self.keywords)
        g4.setLayout(l4)
        layout.addWidget(g4)

        layout.addStretch()
        scroll.setWidget(inner)

        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        return tab

    def _build_sources_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(14)

        # NVD
        g = QGroupBox("NVD (国家漏洞数据库)")
        vbox = QVBoxLayout()
        vbox.setSpacing(10)
        self.nvd_enabled = GlowCheckBox("启用")
        self.nvd_enabled.setChecked(self.config.nvd.enabled)
        vbox.addWidget(self.nvd_enabled)
        self.nvd_api_key = QLineEdit()
        self.nvd_api_key.setText(self.config.nvd.api_key)
        self.nvd_api_key.setPlaceholderText("可选, 有 Key 速率更高")
        self.nvd_api_key.setFixedHeight(34)
        vbox.addLayout(_form_row("API Key:", self.nvd_api_key))
        self.nvd_rate = NoScrollSpinBox()
        self.nvd_rate.setRange(1, 200)
        self.nvd_rate.setValue(self.config.nvd.rate_limit_per_minute)
        self.nvd_rate.setSuffix(" 次/分钟")
        self.nvd_rate.setFixedHeight(34)
        vbox.addLayout(_form_row("请求速率:", self.nvd_rate))
        self.nvd_days = NoScrollSpinBox()
        self.nvd_days.setRange(1, 90)
        self.nvd_days.setValue(self.config.nvd.initial_sync_days)
        self.nvd_days.setSuffix(" 天")
        self.nvd_days.setFixedHeight(34)
        vbox.addLayout(_form_row("回溯天数:", self.nvd_days))
        self.nvd_max = NoScrollSpinBox()
        self.nvd_max.setRange(100, 50000)
        self.nvd_max.setSingleStep(500)
        self.nvd_max.setValue(self.config.nvd.max_records)
        self.nvd_max.setSuffix(" 条")
        self.nvd_max.setFixedHeight(34)
        vbox.addLayout(_form_row("最大拉取:", self.nvd_max))
        g.setLayout(vbox)
        layout.addWidget(g)

        # CISA KEV
        g = QGroupBox("CISA KEV (已知被利用漏洞)")
        vbox = QVBoxLayout()
        self.kev_enabled = GlowCheckBox("启用")
        self.kev_enabled.setChecked(self.config.cisa_kev.enabled)
        vbox.addWidget(self.kev_enabled)
        g.setLayout(vbox)
        layout.addWidget(g)

        # EPSS
        g = QGroupBox("EPSS (漏洞利用预测评分)")
        vbox = QVBoxLayout()
        self.epss_enabled = GlowCheckBox("启用")
        self.epss_enabled.setChecked(self.config.epss.enabled)
        vbox.addWidget(self.epss_enabled)
        g.setLayout(vbox)
        layout.addWidget(g)

        # GitHub
        g = QGroupBox("GitHub Security Advisories")
        vbox = QVBoxLayout()
        vbox.setSpacing(10)
        self.gh_enabled = GlowCheckBox("启用")
        self.gh_enabled.setChecked(self.config.github_advisory.enabled)
        vbox.addWidget(self.gh_enabled)
        self.gh_token = QLineEdit()
        self.gh_token.setText(self.config.github_advisory.token)
        self.gh_token.setPlaceholderText("GitHub Personal Access Token")
        self.gh_token.setEchoMode(QLineEdit.Password)
        self.gh_token.setFixedHeight(34)
        vbox.addLayout(_form_row("Token:", self.gh_token))
        g.setLayout(vbox)
        layout.addWidget(g)

        # OSV
        g = QGroupBox("OSV.dev (开源组件漏洞)")
        vbox = QVBoxLayout()
        self.osv_enabled = GlowCheckBox("启用")
        self.osv_enabled.setChecked(self.config.osv.enabled)
        vbox.addWidget(self.osv_enabled)
        g.setLayout(vbox)
        layout.addWidget(g)

        # CISA RSS
        g = QGroupBox("CISA 安全通告 RSS")
        vbox = QVBoxLayout()
        self.cisa_rss_enabled = GlowCheckBox("启用")
        self.cisa_rss_enabled.setChecked(True)
        vbox.addWidget(self.cisa_rss_enabled)
        g.setLayout(vbox)
        layout.addWidget(g)

        layout.addStretch()
        scroll.setWidget(inner)

        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        return tab

    def _build_scoring_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(6, 6, 6, 6)

        group = QGroupBox("评分权重 (处置价值评分 0-100)")
        form = QFormLayout()
        form.setVerticalSpacing(10)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        self.score_fields = {}
        score_items = [
            ("kev_weight", "CISA KEV 命中"),
            ("epss_95_weight", "EPSS ≥ 0.95"),
            ("epss_85_weight", "EPSS ≥ 0.85"),
            ("cvss_critical_weight", "CVSS ≥ 9.0"),
            ("cvss_high_weight", "CVSS ≥ 7.0"),
            ("recent_24h_weight", "24小时内发布"),
            ("recent_7d_weight", "7天内发布"),
            ("official_confirmed_weight", "官方确认"),
            ("patch_available_weight", "官方补丁可用"),
            ("poc_signal_weight", "公开PoC信号"),
            ("multi_source_confirmed_weight", "多源确认"),
            ("watch_keyword_weight", "命中关注关键词"),
        ]

        for key, label in score_items:
            spin = NoScrollSpinBox()
            spin.setRange(0, 50)
            spin.setValue(getattr(self.config.scoring, key, 0))
            spin.setSuffix(" 分")
            spin.setFixedHeight(34)
            form.addRow(f"{label}:", spin)
            self.score_fields[key] = spin

        group.setLayout(form)
        layout.addWidget(group)
        layout.addStretch()

        scroll.setWidget(inner)

        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        return tab

    def _build_agent_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(14)

        # API Configuration (Protocol → URL → Key → Model)
        g1 = QGroupBox("API 配置")
        l1 = QVBoxLayout()
        l1.setSpacing(10)

        agent_cfg = getattr(self.config, 'agent', None)

        # 1. Protocol
        self.agent_protocol = NoScrollComboBox()
        self.agent_protocol.addItems(["兼容 OpenAI", "兼容 Anthropic"])
        self.agent_protocol.setFixedHeight(34)
        if agent_cfg and getattr(agent_cfg, 'protocol', ''):
            idx = self.agent_protocol.findText(agent_cfg.protocol)
            if idx >= 0:
                self.agent_protocol.setCurrentIndex(idx)
        l1.addLayout(_form_row("兼容协议:", self.agent_protocol))

        # 2. API URL
        self.agent_base_url = QLineEdit()
        self.agent_base_url.setPlaceholderText("如: https://api.openai.com/v1 或 https://api.anthropic.com/v1")
        self.agent_base_url.setFixedHeight(34)
        if agent_cfg:
            self.agent_base_url.setText(getattr(agent_cfg, 'base_url', ''))
        l1.addLayout(_form_row("API 地址:", self.agent_base_url))

        # 3. API Key
        self.agent_api_key = QLineEdit()
        self.agent_api_key.setPlaceholderText("输入 API Key")
        self.agent_api_key.setEchoMode(QLineEdit.Password)
        self.agent_api_key.setFixedHeight(34)
        if agent_cfg:
            self.agent_api_key.setText(getattr(agent_cfg, 'api_key', ''))
        l1.addLayout(_form_row("API Key:", self.agent_api_key))

        # 4. Model
        self.agent_model = QLineEdit()
        self.agent_model.setPlaceholderText("如: gpt-4o, deepseek-chat, claude-3.5-sonnet")
        self.agent_model.setFixedHeight(34)
        if agent_cfg:
            self.agent_model.setText(getattr(agent_cfg, 'model', ''))
        l1.addLayout(_form_row("模型:", self.agent_model))

        # Test connection button
        test_layout = QHBoxLayout()
        test_layout.addStretch()
        self.btn_test_conn = QPushButton("🔗 测试连接")
        self.btn_test_conn.setFixedHeight(32)
        self.btn_test_conn.setStyleSheet("""
            QPushButton {
                background: #1f6feb; color: white; border: 1px solid #388bfd;
                border-radius: 6px; padding: 6px 16px; font-size: 12px;
            }
            QPushButton:hover { background: #388bfd; }
        """)
        self.btn_test_conn.clicked.connect(self._test_connection)
        test_layout.addWidget(self.btn_test_conn)
        l1.addLayout(test_layout)

        # Test result label
        self.test_result = QLabel("")
        self.test_result.setStyleSheet("font-size: 12px; padding: 4px;")
        l1.addWidget(self.test_result)

        g1.setLayout(l1)
        layout.addWidget(g1)

        # Agent Behavior
        g2 = QGroupBox("Agent 行为")
        l2 = QVBoxLayout()
        l2.setSpacing(10)

        self.agent_enabled = GlowCheckBox("启用 AI Agent")
        self.agent_enabled.setChecked(getattr(agent_cfg, 'enabled', False) if agent_cfg else False)
        l2.addWidget(self.agent_enabled)

        self.agent_auto_analysis = GlowCheckBox("打开详情时自动分析")
        self.agent_auto_analysis.setChecked(getattr(agent_cfg, 'auto_analysis', False) if agent_cfg else False)
        l2.addWidget(self.agent_auto_analysis)

        self.agent_db_access = GlowCheckBox("允许访问漏洞数据库")
        self.agent_db_access.setChecked(getattr(agent_cfg, 'db_access', True) if agent_cfg else True)
        l2.addWidget(self.agent_db_access)

        g2.setLayout(l2)
        layout.addWidget(g2)

        # Advanced Config
        g3 = QGroupBox("高级配置")
        l3 = QVBoxLayout()
        l3.setSpacing(10)

        self.agent_max_tokens = NoScrollSpinBox()
        self.agent_max_tokens.setRange(100, 8000)
        self.agent_max_tokens.setValue(getattr(agent_cfg, 'max_tokens', 2000) if agent_cfg else 2000)
        self.agent_max_tokens.setSuffix(" tokens")
        self.agent_max_tokens.setFixedHeight(34)
        l3.addLayout(_form_row("最大Token:", self.agent_max_tokens))

        g3.setLayout(l3)
        layout.addWidget(g3)

        # Prompt
        g4 = QGroupBox("系统提示词")
        l4 = QVBoxLayout()
        self.agent_prompt = QTextEdit()
        self.agent_prompt.setPlaceholderText("你是一个网络安全专家...")
        default_prompt = (
            "你是一个专业的网络安全漏洞分析专家。请根据提供的漏洞信息，从以下维度进行分析：\n"
            "1. 漏洞危害性评估\n2. 影响范围分析\n3. 利用难度评估\n4. 修复建议\n5. 防御措施建议"
        )
        self.agent_prompt.setPlainText(getattr(agent_cfg, 'prompt', default_prompt) if agent_cfg else default_prompt)
        self.agent_prompt.setMaximumHeight(120)
        l4.addWidget(self.agent_prompt)
        g4.setLayout(l4)
        layout.addWidget(g4)

        layout.addStretch()
        scroll.setWidget(inner)

        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        return tab

    def _test_connection(self):
        """Test AI API connection."""
        try:
            import httpx
        except ImportError:
            self.test_result.setText("❌ httpx 未安装")
            self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
            return

        protocol = self.agent_protocol.currentText()
        base_url = self.agent_base_url.text().strip()
        api_key = self.agent_api_key.text().strip()
        model = self.agent_model.text().strip()

        if not base_url:
            self.test_result.setText("❌ 请填写 API 地址")
            self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
            return
        if not api_key:
            self.test_result.setText("❌ 请填写 API Key")
            self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
            return
        if not model:
            self.test_result.setText("❌ 请填写模型名称")
            self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
            return

        self.test_result.setText("⏳ 正在测试连接...")
        self.test_result.setStyleSheet("color: #d29922; font-size: 12px;")
        self.btn_test_conn.setEnabled(False)
        self.btn_test_conn.setText("测试中...")
        QApplication.processEvents()

        try:
            if "Anthropic" in protocol:
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                }
                data = {
                    "model": model,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "ping"}],
                }
                url = f"{base_url.rstrip('/')}/messages"
            else:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                }
                data = {
                    "model": model,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "ping"}],
                }
                url = f"{base_url.rstrip('/')}/chat/completions"

            resp = httpx.post(url, headers=headers, json=data, timeout=15.0)

            if resp.status_code == 200:
                self.test_result.setText("✅ 连接成功!")
                self.test_result.setStyleSheet("color: #3fb950; font-size: 12px;")
            elif resp.status_code == 400:
                try:
                    err = resp.json()
                    detail = err.get("error", {}).get("message", "")
                    if not detail:
                        detail = str(err)[:100]
                except:
                    detail = resp.text[:100]
                self.test_result.setText(f"❌ 400: {detail}")
                self.test_result.setStyleSheet("color: #f85149; font-size: 11px;")
            elif resp.status_code == 401:
                self.test_result.setText("❌ API Key 无效或已过期")
                self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
            elif resp.status_code == 404:
                self.test_result.setText("❌ API 地址或模型不存在")
                self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
            elif resp.status_code == 429:
                self.test_result.setText("❌ 请求过于频繁，请稍后再试")
                self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
            else:
                self.test_result.setText(f"❌ HTTP {resp.status_code}")
                self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
        except httpx.ConnectError:
            self.test_result.setText("❌ 无法连接到服务器")
            self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
        except httpx.TimeoutException:
            self.test_result.setText("❌ 连接超时")
            self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
        except Exception as e:
            self.test_result.setText(f"❌ {str(e)[:60]}")
            self.test_result.setStyleSheet("color: #f85149; font-size: 12px;")
        finally:
            self.btn_test_conn.setEnabled(True)
            self.btn_test_conn.setText("🔗 测试连接")

    def _on_save(self):
        self._result = {
            "refresh_interval_minutes": self.refresh_interval.value(),
            "auto_update_on_startup": self.chk_auto_update_startup.isChecked(),
            "auto_update_enabled": self.chk_auto_update_enabled.isChecked(),
            "update_on_ai_push_startup": self.chk_update_ai_push_startup.isChecked(),
            "min_score_to_badge": self.min_badge.value(),
            "min_score_to_notify": self.min_notify.value(),
            "quiet_hours_enabled": self.quiet_enabled.isChecked(),
            "quiet_hours_start": self.quiet_start.currentText(),
            "quiet_hours_end": self.quiet_end.currentText(),
            "watch_keywords": [
                kw.strip() for kw in self.keywords.text().split(",") if kw.strip()
            ],
            "proxy_enabled": self.proxy_enabled.isChecked(),
            "http_proxy": self.http_proxy.text().strip(),
            "https_proxy": self.https_proxy.text().strip(),
            "nvd_enabled": self.nvd_enabled.isChecked(),
            "nvd_api_key": self.nvd_api_key.text().strip(),
            "nvd_rate_limit": self.nvd_rate.value(),
            "nvd_days": self.nvd_days.value(),
            "nvd_max_records": self.nvd_max.value(),
            "kev_enabled": self.kev_enabled.isChecked(),
            "epss_enabled": self.epss_enabled.isChecked(),
            "gh_enabled": self.gh_enabled.isChecked(),
            "gh_token": self.gh_token.text().strip(),
            "osv_enabled": self.osv_enabled.isChecked(),
            "cisa_rss_enabled": self.cisa_rss_enabled.isChecked(),
            "scoring": {key: spin.value() for key, spin in self.score_fields.items()},
            # Agent
            "agent_enabled": self.agent_enabled.isChecked(),
            "agent_auto_analysis": self.agent_auto_analysis.isChecked(),
            "agent_db_access": self.agent_db_access.isChecked(),
            "agent_protocol": self.agent_protocol.currentText(),
            "agent_api_key": self.agent_api_key.text().strip(),
            "agent_model": self.agent_model.text().strip(),
            "agent_base_url": self.agent_base_url.text().strip(),
            "agent_max_tokens": self.agent_max_tokens.value(),
            "agent_prompt": self.agent_prompt.toPlainText().strip(),
        }
        self.accept()

    def get_result(self) -> dict:
        return getattr(self, "_result", {})
