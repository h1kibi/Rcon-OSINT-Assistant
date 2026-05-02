import os
from datetime import datetime
from PySide6.QtCore import Qt, Signal, QUrl, QTimer
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QGroupBox, QScrollArea, QFrame, QGridLayout, QWidget,
    QFileDialog, QApplication, QMessageBox, QListWidget,
)

DETAIL_STYLE = """
QDialog {
    background: #0d1117; color: #c9d1d9;
    font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QGroupBox {
    font-weight: bold; border: 1px solid #30363d;
    border-radius: 6px; margin-top: 10px; padding-top: 14px;
    color: #58a6ff; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
QLabel { color: #c9d1d9; font-size: 12px; }
QTextEdit {
    border: 1px solid #30363d; border-radius: 4px;
    background: #161b22; color: #c9d1d9;
    font-size: 12px; font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QPushButton {
    padding: 6px 14px; border: 1px solid #30363d;
    border-radius: 4px; font-size: 12px;
    background: #21262d; color: #c9d1d9;
}
QPushButton:hover { background: #30363d; border-color: #58a6ff; }
QPushButton:disabled { background: #161b22; color: #484f58; border-color: #21262d; }
QPushButton#linkBtn {
    text-align: left; border: none; color: #58a6ff;
    font-size: 12px; padding: 3px 4px;
}
QPushButton#linkBtn:hover { color: #79c0ff; text-decoration: underline; }
QScrollArea { border: none; background: #0d1117; }
QLabel#toast {
    background: #238636; color: white; font-size: 12px;
    font-weight: bold; border-radius: 4px; padding: 6px 16px;
}
"""


class DetailWindow(QDialog):
    """Standalone detail window for a single vulnerability."""

    status_changed = Signal(str)

    def __init__(self, vuln: dict, config, parent=None):
        super().__init__(parent)
        self._vuln = vuln
        self._config = config
        self._is_watched = vuln.get("status") == "watched"
        self._is_ignored = vuln.get("status") == "ignored"

        self.setWindowTitle(f"{vuln.get('cve_id', 'N/A')} - 漏洞详情")
        self.setMinimumSize(650, 520)
        self.resize(720, 680)
        self.setStyleSheet(DETAIL_STYLE)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(8)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        content.setStyleSheet("background: #0d1117;")
        self.content_layout = QVBoxLayout(content)
        self.content_layout.setSpacing(8)
        scroll.setWidget(content)
        main_layout.addWidget(scroll)

        # Build content
        self._build_content(vuln)

        # Bottom buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.btn_watch = QPushButton()
        self._update_watch_button()
        self.btn_watch.clicked.connect(self._toggle_watch)

        self.btn_ignore = QPushButton()
        self._update_ignore_button()
        self.btn_ignore.clicked.connect(self._toggle_ignore)

        self.btn_save = QPushButton("保存描述")
        self.btn_save.clicked.connect(self._save_description)

        self.btn_ai = QPushButton("🤖 AI 分析")
        self.btn_ai.setStyleSheet("""
            QPushButton {
                background: #8957e5; color: white; border: 1px solid #a371f7;
                font-weight: bold; border-radius: 4px; font-size: 12px; padding: 6px 14px;
            }
            QPushButton:hover { background: #a371f7; }
            QPushButton:disabled { background: #21262d; color: #484f58; border-color: #30363d; }
        """)
        self._update_ai_button_state()
        self.btn_ai.clicked.connect(self._open_ai_analysis)

        self.btn_history = QPushButton("📁 分析记录")
        self.btn_history.clicked.connect(self._show_analysis_history)
        self._update_history_button()

        self.btn_close = QPushButton("关闭")
        self.btn_close.clicked.connect(self.close)

        btn_layout.addWidget(self.btn_watch)
        btn_layout.addWidget(self.btn_ignore)
        btn_layout.addWidget(self.btn_save)
        btn_layout.addWidget(self.btn_ai)
        btn_layout.addWidget(self.btn_history)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_close)

        main_layout.addLayout(btn_layout)

        # Toast
        self.toast = QLabel(self)
        self.toast.setObjectName("toast")
        self.toast.setAlignment(Qt.AlignCenter)
        self.toast.hide()

        # AI analysis window reference
        self._ai_window = None

    def showEvent(self, event):
        super().showEvent(event)
        if self._vuln.get("status") == "unread":
            self._vuln["status"] = "read"
            self.status_changed.emit("read")

    def _update_ai_button_state(self):
        """Check if API key is configured and update button state."""
        agent_cfg = getattr(self._config, 'agent', None)
        has_key = False
        if agent_cfg:
            api_key = getattr(agent_cfg, 'api_key', '')
            has_key = bool(api_key and api_key.strip())

        if has_key:
            self.btn_ai.setEnabled(True)
            self.btn_ai.setToolTip("")
        else:
            self.btn_ai.setEnabled(False)
            self.btn_ai.setToolTip("请在设置中配置 Agent API Key")

    def _update_history_button(self):
        """Update history button text with count."""
        try:
            from app.utils.analysis_storage import get_analysis_count
            vuln_key = self._vuln.get("cve_id") or self._vuln.get("ghsa_id") or self._vuln.get("osv_id") or ""
            count = get_analysis_count(vuln_key) if vuln_key else 0
            if count > 0:
                self.btn_history.setText(f"📁 分析记录 ({count})")
                self.btn_history.setToolTip(f"查看 {count} 份历史分析")
            else:
                self.btn_history.setText("📁 分析记录")
                self.btn_history.setToolTip("暂无分析记录")
        except:
            pass

    def _show_analysis_history(self):
        """Show analysis history in a dialog."""
        from app.utils.analysis_storage import list_analyses, read_analysis

        vuln_key = self._vuln.get("cve_id") or self._vuln.get("ghsa_id") or self._vuln.get("osv_id") or ""
        if not vuln_key:
            QMessageBox.information(self, "提示", "无漏洞 ID")
            return

        analyses = list_analyses(vuln_key)
        if not analyses:
            QMessageBox.information(self, "分析记录", f"{vuln_key} 暂无分析记录")
            return

        # Create history dialog
        dlg = QDialog(self)
        dlg.setWindowTitle(f"分析记录 - {vuln_key}")
        dlg.setMinimumSize(700, 500)
        dlg.setStyleSheet("""
            QDialog { background: #0d1117; color: #c9d1d9; font-family: 'Microsoft YaHei'; }
            QListWidget { background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
                          border-radius: 6px; font-size: 12px; }
            QListWidget::item { padding: 8px; border-bottom: 1px solid #21262d; }
            QListWidget::item:selected { background: #1f6feb33; color: #58a6ff; }
            QTextBrowser { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;
                        border-radius: 6px; font-size: 13px; }
            QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
                          border-radius: 4px; padding: 6px 14px; font-size: 12px; }
            QPushButton:hover { background: #30363d; border-color: #58a6ff; }
        """)

        layout = QHBoxLayout(dlg)

        # Left: file list
        list_widget = QListWidget()
        for a in analyses:
            list_widget.addItem(f"📄 {a['time']}  ({a['size']})")
        layout.addWidget(list_widget, 1)

        # Right: content viewer (rendered markdown)
        from PySide6.QtWidgets import QTextBrowser
        viewer = QTextBrowser()
        viewer.setOpenExternalLinks(True)
        viewer.setPlaceholderText("选择一份分析记录查看...")
        layout.addWidget(viewer, 2)

        def on_select():
            idx = list_widget.currentRow()
            if 0 <= idx < len(analyses):
                content = read_analysis(analyses[idx]["path"])
                # Render markdown
                from app.ui.ai_analysis_window import md_to_html
                html = md_to_html(content)
                viewer.setHtml(f"""
                <div style="color:#c9d1d9; line-height:1.6; font-size:13px;
                     font-family:'Microsoft YaHei','Consolas',monospace; padding:4px;">
                    {html}
                </div>
                """)

        list_widget.currentRowChanged.connect(lambda _: on_select())

        # Auto-select first
        if analyses:
            list_widget.setCurrentRow(0)

        dlg.exec()

    def _open_ai_analysis(self):
        """Open AI analysis in a new window."""
        from app.ui.ai_analysis_window import AIAnalysisWindow
        if self._ai_window and self._ai_window.isVisible():
            self._ai_window.raise_()
            self._ai_window.activateWindow()
            return
        self._ai_window = AIAnalysisWindow(self._vuln, self._config, self)
        self._ai_window.show()

    def _update_watch_button(self):
        if self._is_watched:
            self.btn_watch.setText("❤ 已关注")
            self.btn_watch.setStyleSheet("""
                QPushButton {
                    background: #da3633; color: white; border: 1px solid #f85149;
                    font-weight: bold; border-radius: 4px; font-size: 12px; padding: 6px 14px;
                }
                QPushButton:hover { background: #f85149; }
            """)
        else:
            self.btn_watch.setText("关注")
            self.btn_watch.setStyleSheet("""
                QPushButton {
                    background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
                    border-radius: 4px; font-size: 12px; padding: 6px 14px;
                }
                QPushButton:hover { background: #30363d; border-color: #58a6ff; }
            """)

    def _update_ignore_button(self):
        if self._is_ignored:
            self.btn_ignore.setText("🚫 已忽略")
            self.btn_ignore.setStyleSheet("""
                QPushButton {
                    background: #484f58; color: #8b949e; border: 1px solid #6e7681;
                    border-radius: 4px; font-size: 12px; padding: 6px 14px;
                }
                QPushButton:hover { background: #6e7681; }
            """)
        else:
            self.btn_ignore.setText("忽略")
            self.btn_ignore.setStyleSheet("""
                QPushButton {
                    background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
                    border-radius: 4px; font-size: 12px; padding: 6px 14px;
                }
                QPushButton:hover { background: #30363d; border-color: #58a6ff; }
            """)

    def _toggle_watch(self):
        if self._is_watched:
            self._is_watched = False
            self._vuln["status"] = "read"
            self.status_changed.emit("read")
            self._update_watch_button()
            self._show_toast("已取消关注")
        else:
            self._is_watched = True
            self._is_ignored = False
            self._vuln["status"] = "watched"
            self.status_changed.emit("watched")
            self._update_watch_button()
            self._update_ignore_button()
            self._show_toast("已添加到关注")

    def _toggle_ignore(self):
        if self._is_ignored:
            self._is_ignored = False
            self._vuln["status"] = "read"
            self.status_changed.emit("read")
            self._update_ignore_button()
            self._show_toast("已取消忽略")
        else:
            self._is_ignored = True
            self._is_watched = False
            self._vuln["status"] = "ignored"
            self.status_changed.emit("ignored")
            self._update_ignore_button()
            self._update_watch_button()
            self._show_toast("已忽略")

    def _flash_button(self, btn, color="#238636", text=None):
        original_style = btn.styleSheet()
        original_text = btn.text()
        btn.setStyleSheet(f"""
            background: {color}; color: white; border: 1px solid {color};
            border-radius: 4px; font-size: 12px; padding: 6px 14px; font-weight: bold;
        """)
        if text:
            btn.setText(text)
        btn.setEnabled(False)
        QTimer.singleShot(800, lambda: (
            btn.setStyleSheet(original_style),
            btn.setText(original_text),
            btn.setEnabled(True),
        ))

    def _show_toast(self, message, duration=1500):
        self.toast.setText(message)
        self.toast.adjustSize()
        x = (self.width() - self.toast.width()) // 2
        y = self.height() - 60
        self.toast.move(x, y)
        self.toast.show()
        QTimer.singleShot(duration, self.toast.hide)

    def _save_description(self):
        v = self._vuln
        cve_id = v.get("cve_id", "unknown")
        default_name = f"{cve_id}_description.txt"
        filepath, _ = QFileDialog.getSaveFileName(
            self, "保存漏洞描述", default_name, "文本文件 (*.txt);;所有文件 (*)"
        )
        if not filepath:
            return
        content = self._generate_report(v)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            self._flash_button(self.btn_save, "#238636", "已保存")
            self._show_toast(f"已保存到 {os.path.basename(filepath)}")
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))

    def _generate_report(self, v):
        report = f"""漏洞ID: {v.get('cve_id', 'N/A')}
标题: {v.get('title', '')}
严重等级: {v.get('severity', 'UNKNOWN')}
CVSS: {v.get('cvss_score', '-')}
CVSS向量: {v.get('cvss_vector', '-')}
EPSS: {v.get('epss_score', '-')}
EPSS百分位: {v.get('epss_percentile', '-')}
KEV: {'是' if v.get('is_kev') else '否'}
PoC: {'是' if v.get('has_poc_signal') else '否'}
补丁: {'是' if v.get('has_patch') else '否'}
官方确认: {'是' if v.get('official_confirmed') else '否'}
来源: {v.get('source', '-')}
来源可信度: {v.get('source_confidence_score', 50):.0f}%
发布时间: {v.get('published_at', '-')}
处置评分: {v.get('action_value_score', 0):.0f}/100

评分依据:
{v.get('action_value_reason', '')}

漏洞描述:
{v.get('description', '')}

影响产品:
"""
        products = v.get("affected_products", [])
        if isinstance(products, list):
            for p in products:
                if isinstance(p, dict):
                    vendor = p.get("vendor", "")
                    prod = p.get("product", p.get("package_name", ""))
                    fixed = p.get("fixed_version", "")
                    report += f"  - {vendor} {prod}"
                    if fixed:
                        report += f" (修复版本: {fixed})"
                    report += "\n"

        report += "\n参考链接:\n"
        refs = v.get("references", [])
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, dict):
                    report += f"  - {r.get('url', '')}\n"
        return report

    def _build_content(self, vuln: dict):
        title = QLabel(vuln.get("title", vuln.get("cve_id", "Unknown")))
        title.setWordWrap(True)
        title.setStyleSheet("font-size:16px; font-weight:bold; color:#e6edf3;")
        self.content_layout.addWidget(title)

        score = vuln.get("action_value_score", 0) or 0
        if score >= 80:
            score_color, level = "#f85149", "极高风险"
        elif score >= 60:
            score_color, level = "#d29922", "高风险"
        elif score >= 40:
            score_color, level = "#58a6ff", "中等风险"
        else:
            score_color, level = "#484f58", "低风险"

        score_label = QLabel(f"  处置价值评分: {score:.0f} / 100  [{level}]")
        score_label.setStyleSheet(
            f"font-size:14px; font-weight:bold; color:white; "
            f"background:{score_color}; border-radius:6px; padding:6px 14px;"
        )
        self.content_layout.addWidget(score_label)

        tags_layout = QHBoxLayout()
        tags_layout.setSpacing(6)
        if vuln.get("is_kev"):
            tags_layout.addWidget(self._tag("KEV 已利用", "#f85149"))
        if vuln.get("has_poc_signal"):
            tags_layout.addWidget(self._tag("PoC 公开", "#d29922"))
        if vuln.get("has_patch"):
            tags_layout.addWidget(self._tag("已有补丁", "#3fb950"))
        if vuln.get("official_confirmed"):
            tags_layout.addWidget(self._tag("官方确认", "#58a6ff"))
        if vuln.get("kev_known_ransomware"):
            tags_layout.addWidget(self._tag("勒索软件利用", "#f85149"))
        tags_layout.addStretch()
        self.content_layout.addLayout(tags_layout)

        self._add_section("基本信息", [
            ("CVE ID", vuln.get("cve_id", "-")),
            ("GHSA ID", vuln.get("ghsa_id", "-")),
            ("严重等级", vuln.get("severity", "UNKNOWN")),
            ("CVSS 评分", f"{vuln.get('cvss_score'):.1f}" if vuln.get("cvss_score") else "-"),
            ("CVSS 向量", vuln.get("cvss_vector", "-")),
            ("EPSS 分数", f"{vuln.get('epss_score'):.4f}" if vuln.get("epss_score") else "-"),
            ("EPSS 百分位", f"{vuln.get('epss_percentile', 0) * 100:.1f}%" if vuln.get("epss_percentile") else "-"),
            ("CISA KEV", "是" if vuln.get("is_kev") else "否"),
            ("官方确认", "是" if vuln.get("official_confirmed") else "否"),
            ("官方补丁", "是" if vuln.get("has_patch") else "否"),
            ("公开 PoC", "是" if vuln.get("has_poc_signal") else "否"),
            ("数据来源", vuln.get("source", "-")),
            ("来源可信度", f"{vuln.get('source_confidence_score', 50):.0f}%"),
            ("当前状态", vuln.get("status", "-")),
        ])

        # Time section
        self._add_section("时间信息", [
            ("最早公开时间", _fmt_dt(vuln.get("disclosed_at"))),
            ("时间来源", vuln.get("disclosed_source", "-")),
            ("主来源发布时间", _fmt_dt(vuln.get("published_at"))),
            ("最后更新时间", _fmt_dt(vuln.get("modified_at"))),
            ("本地首次发现", _fmt_dt(vuln.get("first_seen_at"))),
            ("本地最后看到", _fmt_dt(vuln.get("last_seen_at"))),
        ])

        # Source timeline
        source_records = vuln.get("source_records", [])
        if source_records:
            self._add_source_timeline(source_records)

        reason_text = vuln.get("action_value_reason", "")
        if reason_text:
            self._add_text_section("评分依据", reason_text)

        desc = vuln.get("description", "")
        if desc:
            self._add_text_section("漏洞描述", desc)

        products = vuln.get("affected_products", [])
        if isinstance(products, list) and products:
            prod_lines = []
            for p in products:
                if isinstance(p, dict):
                    vendor = p.get("vendor", "")
                    prod = p.get("product", p.get("package_name", ""))
                    fixed = p.get("fixed_version", "")
                    eco = p.get("package_ecosystem", "")
                    line = f"{vendor} {prod}"
                    if eco:
                        line += f" [{eco}]"
                    if fixed:
                        line += f"  ->  修复版本: {fixed}"
                    prod_lines.append(line)
            if prod_lines:
                self._add_text_section("影响产品 / 组件", "\n".join(prod_lines))

        refs = vuln.get("references", [])
        if isinstance(refs, list) and refs:
            self._add_refs_section("参考链接", refs)

        self.content_layout.addStretch()

    def _tag(self, text, color):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"background:{color}; color:white; font-size:11px; "
            f"font-weight:bold; border-radius:3px; padding:3px 8px;"
        )
        lbl.setFixedHeight(20)
        return lbl

    def _add_section(self, title, fields):
        group = QGroupBox(title)
        grid = QGridLayout()
        grid.setSpacing(4)
        grid.setContentsMargins(10, 14, 10, 10)
        for i, (label, value) in enumerate(fields):
            lbl = QLabel(f"{label}:")
            lbl.setStyleSheet("color:#484f58; font-size:12px;")
            val = QLabel(str(value)[:300])
            val.setWordWrap(True)
            val.setStyleSheet("color:#c9d1d9; font-size:12px;")
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
        te.setMaximumHeight(200)
        te.setStyleSheet("border:none;")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 14, 10, 10)
        layout.addWidget(te)
        self.content_layout.addWidget(group)

    def _add_refs_section(self, title, refs):
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 14, 10, 10)
        layout.setSpacing(3)
        for ref in refs[:15]:
            if isinstance(ref, dict):
                url = ref.get("url", "")
                source = ref.get("source", "")
                text = f"{url}  [{source}]"
            else:
                text = str(ref)
                url = str(ref)
            btn = QPushButton(text[:120])
            btn.setObjectName("linkBtn")
            btn.setFlat(True)
            btn.clicked.connect(lambda _, u=url: QDesktopServices.openUrl(QUrl(u)))
            layout.addWidget(btn)
        self.content_layout.addWidget(group)

    def _add_source_timeline(self, records):
        lines = []
        for r in records:
            source = getattr(r, "source", r.get("source", "")) if isinstance(r, dict) else getattr(r, "source", "")
            pub = _fmt_dt(getattr(r, "published_at", None) if not isinstance(r, dict) else r.get("published_at"))
            mod = _fmt_dt(getattr(r, "modified_at", None) if not isinstance(r, dict) else r.get("modified_at"))
            fetch = _fmt_dt(getattr(r, "fetched_at", None) if not isinstance(r, dict) else r.get("fetched_at"))
            url = getattr(r, "url", "") if not isinstance(r, dict) else r.get("url", "")
            lines.append(f"{source}\n  发布: {pub}\n  更新: {mod}\n  抓取: {fetch}\n  链接: {url}")

        if lines:
            self._add_text_section("来源时间线", "\n\n".join(lines))


from datetime import datetime, timezone


def _fmt_dt(value) -> str:
    if not value:
        return "-"
    if isinstance(value, str):
        return value.replace("T", " ").replace("Z", " UTC")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.strftime("%Y-%m-%d %H:%M:%S UTC")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)
