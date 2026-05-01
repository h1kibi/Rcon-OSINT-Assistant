from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QGroupBox, QScrollArea, QFrame, QGridLayout,
)

# Dark theme for detail panel
DETAIL_STYLE = """
QGroupBox {
    font-weight: bold; border: 1px solid #30363d;
    border-radius: 6px; margin-top: 10px; padding-top: 14px;
    color: #58a6ff; font-size: 11px;
    font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
QLabel { color: #c9d1d9; font-size: 12px; font-family: 'Microsoft YaHei', monospace; }
QTextEdit {
    border: 1px solid #30363d; border-radius: 4px;
    background: #0d1117; color: #c9d1d9;
    font-size: 11px; font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QPushButton {
    padding: 5px 12px; border: 1px solid #30363d;
    border-radius: 4px; font-size: 11px;
    background: #21262d; color: #c9d1d9;
    font-family: 'Microsoft YaHei', monospace;
}
QPushButton:hover { background: #30363d; border-color: #58a6ff; }
QPushButton#actionBtn { background: #238636; color: white; border-color: #2ea043; }
QPushButton#actionBtn:hover { background: #2ea043; }
QPushButton#linkBtn {
    text-align: left; border: none; color: #58a6ff;
    font-size: 11px; padding: 2px 4px;
}
QPushButton#linkBtn:hover { color: #79c0ff; text-decoration: underline; }
QScrollArea { border: none; background: #0d1117; }
"""


class DetailPanel(QWidget):
    """Right-side detail panel showing vulnerability info."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(320)
        self.setMaximumWidth(480)
        self._vuln: dict | None = None
        self.setStyleSheet(DETAIL_STYLE)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)

        self.content = QWidget()
        self.content.setStyleSheet("background: #0d1117;")
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setSpacing(6)

        self.scroll.setWidget(self.content)
        layout.addWidget(self.scroll)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(6)

        self.btn_read = QPushButton("已读")
        self.btn_read.setObjectName("actionBtn")
        self.btn_watched = QPushButton("关注")
        self.btn_ignore = QPushButton("忽略")
        self.btn_copy = QPushButton("复制")

        for btn in [self.btn_read, self.btn_watched, self.btn_ignore, self.btn_copy]:
            btn.setFixedHeight(28)
            btn_layout.addWidget(btn)

        layout.addLayout(btn_layout)
        self.setVisible(False)

    def show_vuln(self, vuln: dict):
        self._vuln = vuln
        self._build_content(vuln)
        self.setVisible(True)

    def clear(self):
        self._vuln = None
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.setVisible(False)

    def _build_content(self, vuln: dict):
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Title
        title = QLabel(vuln.get("title", vuln.get("cve_id", "Unknown")))
        title.setWordWrap(True)
        title.setStyleSheet("font-size:14px; font-weight:bold; color:#e6edf3;")
        self.content_layout.addWidget(title)

        # Score badge
        score = vuln.get("action_value_score", 0) or 0
        if score >= 80:
            score_color = "#f85149"
            level = "极高"
        elif score >= 60:
            score_color = "#d29922"
            level = "高"
        elif score >= 40:
            score_color = "#58a6ff"
            level = "中"
        else:
            score_color = "#484f58"
            level = "低"

        score_label = QLabel(f"  处置评分 {score:.0f}/100  [{level}]")
        score_label.setStyleSheet(
            f"font-size:13px; font-weight:bold; color:white; "
            f"background:{score_color}; border-radius:4px; padding:4px 10px;"
        )
        self.content_layout.addWidget(score_label)

        # Tags row
        tags_layout = QHBoxLayout()
        tags_layout.setSpacing(4)
        if vuln.get("is_kev"):
            tags_layout.addWidget(self._tag("KEV 已利用", "#f85149"))
        if vuln.get("has_poc_signal"):
            tags_layout.addWidget(self._tag("PoC 公开", "#d29922"))
        if vuln.get("has_patch"):
            tags_layout.addWidget(self._tag("已有补丁", "#3fb950"))
        if vuln.get("official_confirmed"):
            tags_layout.addWidget(self._tag("官方确认", "#58a6ff"))
        tags_layout.addStretch()
        self.content_layout.addLayout(tags_layout)

        # Info grid
        self._add_section("基本信息", [
            ("CVE ID", vuln.get("cve_id", "-")),
            ("严重等级", vuln.get("severity", "UNKNOWN")),
            ("CVSS 评分", f"{vuln.get('cvss_score'):.1f}" if vuln.get("cvss_score") else "-"),
            ("CVSS 向量", vuln.get("cvss_vector", "-")),
            ("EPSS 分数", f"{vuln.get('epss_score'):.4f}" if vuln.get("epss_score") else "-"),
            ("EPSS 百分位", f"{vuln.get('epss_percentile', 0) * 100:.1f}%" if vuln.get("epss_percentile") else "-"),
            ("数据来源", vuln.get("source", "-")),
            ("来源可信度", f"{vuln.get('source_confidence_score', 50):.0f}%"),
            ("发布时间", str(vuln.get("published_at", "-"))[:10]),
            ("状态", vuln.get("status", "-")),
        ])

        # Scoring reasons
        reason_text = vuln.get("action_value_reason", "")
        if reason_text:
            self._add_text_section("评分依据", reason_text)

        # Description
        desc = vuln.get("description", "")
        if desc:
            self._add_text_section("漏洞描述", desc[:500])

        # Affected products
        products = vuln.get("affected_products", [])
        if isinstance(products, list) and products:
            prod_lines = []
            for p in products[:5]:
                if isinstance(p, dict):
                    vendor = p.get("vendor", "")
                    prod = p.get("product", p.get("package_name", ""))
                    fixed = p.get("fixed_version", "")
                    eco = p.get("package_ecosystem", "")
                    line = f"{vendor} {prod}"
                    if eco:
                        line += f" [{eco}]"
                    if fixed:
                        line += f" -> 修复版本: {fixed}"
                    prod_lines.append(line)
            if prod_lines:
                self._add_text_section("影响产品", "\n".join(prod_lines))

        # References
        refs = vuln.get("references", [])
        if isinstance(refs, list) and refs:
            self._add_refs_section("参考链接", refs)

        self.content_layout.addStretch()

    def _tag(self, text, color):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"background:{color}; color:white; font-size:10px; "
            f"font-weight:bold; border-radius:3px; padding:2px 6px;"
        )
        lbl.setFixedHeight(18)
        return lbl

    def _add_section(self, title, fields):
        group = QGroupBox(title)
        grid = QGridLayout()
        grid.setSpacing(3)
        grid.setContentsMargins(8, 12, 8, 8)
        for i, (label, value) in enumerate(fields):
            lbl = QLabel(f"{label}:")
            lbl.setStyleSheet("color:#484f58; font-size:11px;")
            val = QLabel(str(value)[:200])
            val.setWordWrap(True)
            val.setStyleSheet("color:#c9d1d9; font-size:11px;")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(lbl, i, 0)
            grid.addWidget(val, i, 1)
        group.setLayout(grid)
        self.content_layout.addWidget(group)

    def _add_text_section(self, title, text):
        group = QGroupBox(title)
        te = QTextEdit()
        te.setReadOnly(True)
        te.setPlainText(text)
        te.setMaximumHeight(150)
        te.setStyleSheet("border:none; font-size:11px;")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.addWidget(te)
        self.content_layout.addWidget(group)

    def _add_refs_section(self, title, refs):
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(2)
        for ref in refs[:10]:
            if isinstance(ref, dict):
                url = ref.get("url", "")
                source = ref.get("source", "")
                text = f"{url}"
            else:
                text = str(ref)
                url = str(ref)
            btn = QPushButton(text[:100])
            btn.setObjectName("linkBtn")
            btn.setFlat(True)
            btn.clicked.connect(lambda _, u=url: QDesktopServices.openUrl(QUrl(u)))
            layout.addWidget(btn)
        self.content_layout.addWidget(group)

    def connect_buttons(self, mark_read_fn, mark_watched_fn, ignore_fn, copy_fn):
        self.btn_read.clicked.connect(mark_read_fn)
        self.btn_watched.clicked.connect(mark_watched_fn)
        self.btn_ignore.clicked.connect(ignore_fn)
        self.btn_copy.clicked.connect(copy_fn)
