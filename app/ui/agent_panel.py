"""Rcon AI Panel — immersive landing page and chat for vulnerability intelligence."""

import json
import re
from PySide6.QtCore import Qt, Signal, QThread, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QApplication, QSizePolicy, QGraphicsDropShadowEffect,
    QScrollArea, QGridLayout,
)
from loguru import logger

from app.ui.chat_widgets import ChatMessageWidget, ChatComposer, render_markdown
from app.ui.chat_animations import animate_message_in, smooth_scroll_to_bottom, TypewriterRenderer
from app.services.agent_tools import AgentToolService
from app.services.agent_service import AgentService
from app.services.agent_worker import AgentWorker

CENTER_MAX_WIDTH = 1040
COMPOSER_MAX_WIDTH = 980

# ─── Colors ───────────────────────────────────────────────────────────
C = {
    "bg":        "#080b11",
    "surface":   "rgba(17, 24, 39, 0.96)",
    "border":    "rgba(148, 163, 184, 0.12)",
    "border_f":  "rgba(96, 165, 250, 0.55)",
    "blue":      "#3b82f6",
    "blue2":     "#2563eb",
    "text":      "#e5e7eb",
    "text2":     "#9ca3af",
    "text3":     "#7f8da3",
    "white":     "#f9fafb",
}

AGENT_STYLE = f"""
QWidget#agentPanel {{
    background: {C['bg']};
    color: {C['text']};
    font-family: "Microsoft YaHei", "Inter", "Segoe UI";
}}

QFrame#agentTopBar {{
    background: #0b0f17;
    border-bottom: 1px solid {C['border']};
}}

QLabel#agentTitle {{
    color: #f9fafb;
    font-size: 16px;
    font-weight: 800;
}}

QLabel#agentSubtitle {{
    color: {C['text3']};
    font-size: 12px;
}}

QWidget#agentPanel QFrame#assistantBubble {{
    background: #111827;
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 18px;
}}

QWidget#agentPanel QFrame#userBubble {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 {C['blue2']}, stop:1 #7c3aed);
    border: none;
    border-radius: 18px;
}}

QWidget#agentPanel QLabel#userAvatar {{
    color: {C['bg']};
    background: {C['text']};
    border-radius: 15px;
    font-weight: 800;
}}

QWidget#agentPanel QLabel#assistantAvatar {{
    color: white;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #38bdf8, stop:1 #8b5cf6);
    border-radius: 15px;
    font-weight: 800;
}}

QWidget#agentPanel QTextBrowser#messageBody {{
    background: transparent;
    color: {C['text']};
    border: none;
    font-size: 14px;
    line-height: 150%;
}}

QWidget#agentPanel QFrame#composerWrap {{
    background: {C['bg']};
    border-top: none;
}}

QWidget#agentPanel QFrame#composerShell {{
    background: {C['surface']};
    border: 1px solid {C['border']};
    border-radius: 26px;
}}

QWidget#agentPanel QFrame#composerShell[focused="true"] {{
    border: 1px solid {C['border_f']};
    background: rgba(17, 24, 39, 1.0);
}}

QWidget#agentPanel QTextEdit#composerInput {{
    background: transparent;
    color: #f9fafb;
    border: none;
    font-size: 14px;
    padding: 2px;
}}

QWidget#agentPanel QPushButton#sendCircle {{
    background: #f9fafb;
    color: #0b0f17;
    border: none;
    border-radius: 19px;
    font-size: 18px;
    font-weight: 900;
}}

QWidget#agentPanel QPushButton#sendCircle:hover {{
    background: #dbeafe;
}}

QWidget#agentPanel QPushButton#newBtn {{
    background: rgba(17, 24, 39, 0.72);
    color: {C['blue']};
    border: 1px solid {C['border']};
    border-radius: 14px;
    padding: 5px 16px;
    font-size: 12px;
}}

QWidget#agentPanel QPushButton#newBtn:hover {{
    background: rgba(30, 41, 59, 0.82);
    border-color: {C['border_f']};
}}

QWidget#agentPanel QPushButton#linkBtn {{
    background: transparent;
    color: {C['blue']};
    border: none;
    font-size: 12px;
}}

QWidget#agentPanel QPushButton#linkBtn:hover {{ color: {C['text']}; }}

QWidget#agentPanel QFrame#chipFrame {{
    background: {C['bg']};
    border-top: 1px solid {C['border']};
}}

QWidget#agentPanel QPushButton#chipBtn {{
    background: rgba(17, 24, 39, 0.72);
    color: {C['text2']};
    border: 1px solid {C['border']};
    border-radius: 16px;
    padding: 7px 16px;
    font-size: 12px;
}}

QWidget#agentPanel QPushButton#chipBtn:hover {{
    background: rgba(30, 41, 59, 0.82);
    color: {C['text']};
    border-color: {C['border_f']};
}}

QWidget#agentPanel QScrollArea {{ background: {C['bg']}; border: none; }}
QWidget#agentPanel QScrollBar:vertical {{
    background: {C['bg']}; width: 5px; border: none;
}}
QWidget#agentPanel QScrollBar::handle:vertical {{
    background: rgba(148,163,184,0.18); border-radius: 2px; min-height: 30px;
}}
QWidget#agentPanel QScrollBar::handle:vertical:hover {{ background: rgba(148,163,184,0.32); }}
QWidget#agentPanel QScrollBar::add-line:vertical, QWidget#agentPanel QScrollBar::sub-line:vertical {{ height: 0; }}

/* Dashboard */
QFrame#heroCard {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #111827, stop:0.55 #0f172a, stop:1 #111827);
    border: 1px solid rgba(96,165,250,0.18);
    border-radius: 28px;
}}

QLabel#heroTitle {{
    color: #f9fafb;
    font-size: 30px;
    font-weight: 900;
}}

QLabel#heroSubtitle {{
    color: #9ca3af;
    font-size: 14px;
}}

QLabel#sectionTitle {{
    color: #9ca3af;
    font-size: 13px;
    font-weight: 600;
}}

/* MetricPill */
QFrame#metricPill {{
    background: rgba(17,24,39,0.82);
    border: 1px solid {C['border']};
    border-radius: 18px;
}}

QLabel#metricValue {{
    font-size: 25px;
    font-weight: 850;
    font-family: Consolas;
}}

QLabel#metricLabel {{
    color: #8b98aa;
    font-size: 12px;
}}

/* PromptCard */
QFrame#promptCard {{
    background: rgba(17,24,39,0.72);
    border: 1px solid {C['border']};
    border-radius: 20px;
}}

QFrame#promptCard:hover {{
    background: rgba(30,41,59,0.82);
    border: 1px solid rgba(96,165,250,0.38);
}}

QLabel#promptTitle {{
    color: #f3f4f6;
    font-size: 14px;
    font-weight: 750;
}}

QLabel#promptDesc {{
    color: #8b98aa;
    font-size: 12px;
}}

QLabel#promptBadge {{
    color: #60a5fa;
    background: rgba(96,165,250,0.12);
    border: 1px solid rgba(96,165,250,0.28);
    border-radius: 10px;
    font-size: 10px;
    font-weight: 700;
    font-family: Consolas;
}}

/* RiskFeedCard */
QFrame#riskFeedCard {{
    background: rgba(17,24,39,0.68);
    border: 1px solid {C['border']};
    border-radius: 18px;
}}

QFrame#riskFeedCard:hover {{
    background: rgba(24,34,51,0.86);
    border-color: rgba(96,165,250,0.32);
}}

QLabel#riskCve {{
    color: #60a5fa;
    font-size: 13px;
    font-weight: 800;
    font-family: Consolas;
}}

QLabel#riskTitle {{
    color: #d1d5db;
    font-size: 13px;
}}

QLabel#riskMeta {{
    color: {C['text3']};
    font-size: 11px;
}}

QLabel#riskScore {{
    color: #f9fafb;
    background: rgba(37,99,235,0.18);
    border: 1px solid rgba(96,165,250,0.32);
    border-radius: 26px;
    font-size: 18px;
    font-weight: 900;
    font-family: Consolas;
}}
"""


# ─── Metric Pill ──────────────────────────────────────────────────────
class MetricPill(QFrame):
    def __init__(self, label: str, value: str, accent: str, parent=None):
        super().__init__(parent)
        self.setObjectName("metricPill")
        self.setMinimumHeight(76)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        self.value_label = QLabel(str(value))
        self.value_label.setObjectName("metricValue")
        self.value_label.setStyleSheet(f"color: {accent};")
        layout.addWidget(self.value_label)

        lbl = QLabel(label)
        lbl.setObjectName("metricLabel")
        layout.addWidget(lbl)

    def set_value(self, value):
        self.value_label.setText(str(value))


# ─── Prompt Card ──────────────────────────────────────────────────────
class PromptCard(QFrame):
    clicked = Signal(str)

    def __init__(self, title: str, desc: str, prompt: str, badge: str = "", parent=None):
        super().__init__(parent)
        self.prompt = prompt
        self.setObjectName("promptCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(112)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        head = QLabel(title)
        head.setObjectName("promptTitle")
        layout.addWidget(head)

        body = QLabel(desc)
        body.setObjectName("promptDesc")
        body.setWordWrap(True)
        layout.addWidget(body)

        layout.addStretch(1)

        if badge:
            self._badge = QLabel(badge)
            self._badge.setObjectName("promptBadge")
            self._badge.setAlignment(Qt.AlignCenter)
            self._badge.setFixedSize(36, 20)
            layout.addWidget(self._badge, 0, Qt.AlignRight)

    def mousePressEvent(self, event):
        self.clicked.emit(self.prompt)


# ─── Risk Feed Card ───────────────────────────────────────────────────
class RiskFeedCard(QFrame):
    clicked = Signal(dict)

    def __init__(self, data: dict, parent=None):
        super().__init__(parent)
        self._data = data
        self.setObjectName("riskFeedCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(86)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(14)

        left = QVBoxLayout()
        left.setSpacing(6)

        cve = QLabel(data.get("cve_id", "N/A"))
        cve.setObjectName("riskCve")
        left.addWidget(cve)

        title = QLabel(data.get("title", ""))
        title.setObjectName("riskTitle")
        title.setWordWrap(True)
        title.setMaximumHeight(38)
        left.addWidget(title)

        meta = QLabel(self._meta_text(data))
        meta.setObjectName("riskMeta")
        left.addWidget(meta)

        layout.addLayout(left, 1)

        score = data.get("score", 0) or 0
        badge = QLabel(f"{score:.0f}")
        badge.setObjectName("riskScore")
        badge.setAlignment(Qt.AlignCenter)
        badge.setFixedSize(52, 52)
        layout.addWidget(badge)

    def _meta_text(self, data: dict) -> str:
        parts = []
        if data.get("cvss"):
            parts.append(f"CVSS {data['cvss']:.1f}")
        if data.get("is_kev"):
            parts.append("KEV")
        if data.get("has_poc"):
            parts.append("PoC")
        sev = data.get("severity")
        if sev:
            parts.append(str(sev).upper())
        return " · ".join(parts) or "暂无结构化风险标签"

    def mousePressEvent(self, event):
        self.clicked.emit(self._data)


# ─── Main Agent Panel ─────────────────────────────────────────────────
class AgentPanel(QWidget):

    def __init__(self, config, db_session_factory, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db_session_factory
        self.setObjectName("agentPanel")
        self._worker = None
        self._history: list[dict] = []
        self._current_vuln = None
        self._streaming = False
        self._current_stream: TypewriterRenderer | None = None
        self._current_ai_msg: ChatMessageWidget | None = None
        self._busy = False
        self._request_id = 0

        self.tools = AgentToolService(db_session_factory)
        self.agent_service = AgentService(lambda: self.config, self.tools)

        self._build_ui()
        self._apply_style()
        self._load_dashboard()

    def set_current_vuln(self, v):
        self._current_vuln = v

    # ── Build UI ────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top Bar ────────────────────────────────────────────────
        top = QFrame()
        top.setObjectName("agentTopBar")
        top.setFixedHeight(48)
        tb = QHBoxLayout(top)
        tb.setContentsMargins(24, 0, 16, 0)

        title = QLabel("Rcon AI")
        title.setObjectName("agentTitle")
        tb.addWidget(title)
        tb.addSpacing(10)
        subtitle = QLabel("本地漏洞情报助手")
        subtitle.setObjectName("agentSubtitle")
        tb.addWidget(subtitle)
        tb.addStretch()

        self.btn_new = QPushButton("+ 新对话")
        self.btn_new.setObjectName("newBtn")
        self.btn_new.setCursor(Qt.PointingHandCursor)
        self.btn_new.clicked.connect(self._clear)
        tb.addWidget(self.btn_new)

        root.addWidget(top)

        # ── Content Stack ──────────────────────────────────────────
        self.content_stack = QWidget()
        self.content_layout = QVBoxLayout(self.content_stack)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)

        # Dashboard view
        self.dashboard = self._build_dashboard()
        self.content_layout.addWidget(self.dashboard)

        # Chat view (hidden initially)
        self.chat_scroll = QScrollArea()
        self.chat_scroll.setWidgetResizable(True)
        self.chat_scroll.setFrameShape(QFrame.NoFrame)
        self.chat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.chat_container = QWidget()
        self.chat_container.setObjectName("chatPage")
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setContentsMargins(0, 36, 0, 36)
        self.chat_layout.setSpacing(8)
        self.chat_layout.addStretch(1)
        self.chat_scroll.setWidget(self.chat_container)
        self.chat_scroll.hide()
        self.content_layout.addWidget(self.chat_scroll)

        root.addWidget(self.content_stack, 1)

        # ── Quick Actions Chips ────────────────────────────────────
        self.chip_frame = QFrame()
        self.chip_frame.setObjectName("chipFrame")
        chip_l = QHBoxLayout(self.chip_frame)
        chip_l.setContentsMargins(20, 10, 20, 6)
        chip_l.setSpacing(10)

        for label, icon in [("数据库概览", "📊"), ("最近漏洞", "🕐"), ("高危 Top10", "🔥")]:
            btn = QPushButton(f"{icon}  {label}")
            btn.setObjectName("chipBtn")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, l=label: self._on_chip(l))
            chip_l.addWidget(btn)
        chip_l.addStretch()
        root.addWidget(self.chip_frame)

        # ── Composer (centered max-width) ──────────────────────────
        composer_wrap = QFrame()
        composer_wrap.setObjectName("composerWrap")
        wrap_l = QHBoxLayout(composer_wrap)
        wrap_l.setContentsMargins(32, 10, 32, 18)
        wrap_l.setSpacing(0)

        self.composer = ChatComposer()
        self.composer.setMaximumWidth(COMPOSER_MAX_WIDTH)
        self.composer.submitted.connect(self._send)

        wrap_l.addStretch(1)
        wrap_l.addWidget(self.composer, 1)
        wrap_l.addStretch(1)

        root.addWidget(composer_wrap)

    def _build_dashboard(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        page = QWidget()
        page_layout = QHBoxLayout(page)
        page_layout.setContentsMargins(32, 32, 32, 28)
        page_layout.setSpacing(0)

        shell = QFrame()
        shell.setObjectName("dashboardShell")
        shell.setMaximumWidth(CENTER_MAX_WIDTH)

        layout = QVBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(22)

        # ── Hero ────────────────────────────────────────────────────
        hero = QFrame()
        hero.setObjectName("heroCard")
        hero_l = QVBoxLayout(hero)
        hero_l.setContentsMargins(28, 28, 28, 28)
        hero_l.setSpacing(10)

        hero_title = QLabel("Rcon AI")
        hero_title.setObjectName("heroTitle")
        hero_l.addWidget(hero_title)

        hero_sub = QLabel("询问漏洞、CVE、KEV、EPSS、修复优先级")
        hero_sub.setObjectName("heroSubtitle")
        hero_sub.setWordWrap(True)
        hero_l.addWidget(hero_sub)

        layout.addWidget(hero)

        # ── Metrics ─────────────────────────────────────────────────
        metrics = QHBoxLayout()
        metrics.setSpacing(12)

        self.card_total = MetricPill("总漏洞", "—", "#93c5fd")
        self.card_kev = MetricPill("KEV 命中", "—", "#fca5a5")
        self.card_unread = MetricPill("未读", "—", "#fcd34d")
        self.card_high = MetricPill("高危 ≥80", "—", "#f87171")

        for card in [self.card_total, self.card_kev, self.card_unread, self.card_high]:
            metrics.addWidget(card)

        layout.addLayout(metrics)

        # ── Prompt Cards ────────────────────────────────────────────
        prompt_grid = QGridLayout()
        prompt_grid.setSpacing(12)

        prompts = [
            ("今日优先处置", "让 Rcon 汇总当前最值得优先修复的风险。",
             "根据本地漏洞数据库，总结当前最值得优先处置的漏洞，并说明排序原因。", "P1"),
            ("KEV 命中分析", "查看存在在野利用证据的关键漏洞。",
             "高危 Top10", "KEV"),
            ("最近新增漏洞", "快速浏览最近同步进来的漏洞情报。",
             "最近漏洞", "NEW"),
            ("修复优先级清单", "生成面向安全运营的处置建议。",
             "请根据当前漏洞库生成一份修复优先级清单，按紧急程度分组，并给出修复建议。", "FIX"),
        ]

        for i, (p_title, desc, prompt, badge) in enumerate(prompts):
            card = PromptCard(p_title, desc, prompt, badge)
            card.clicked.connect(self._send_prompt)
            prompt_grid.addWidget(card, i // 2, i % 2)

        layout.addLayout(prompt_grid)

        # ── Recent Risk Feed ────────────────────────────────────────
        header = QHBoxLayout()
        label = QLabel("最近风险动态")
        label.setObjectName("sectionTitle")
        header.addWidget(label)
        header.addStretch()

        self.btn_more = QPushButton("查看全部 →")
        self.btn_more.setObjectName("linkBtn")
        self.btn_more.setCursor(Qt.PointingHandCursor)
        self.btn_more.clicked.connect(lambda: self._on_chip("最近漏洞"))
        header.addWidget(self.btn_more)

        layout.addLayout(header)

        self.vuln_list = QVBoxLayout()
        self.vuln_list.setSpacing(8)
        layout.addLayout(self.vuln_list)

        layout.addStretch(1)

        page_layout.addStretch(1)
        page_layout.addWidget(shell, 1)
        page_layout.addStretch(1)

        scroll.setWidget(page)
        return scroll

    # ── Dashboard Data ──────────────────────────────────────────────
    def _clear_vuln_list(self):
        while self.vuln_list.count():
            item = self.vuln_list.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def refresh_dashboard(self):
        self._load_dashboard()

    def _load_dashboard(self):
        try:
            self._clear_vuln_list()
            stats = self.tools.stats()
            self.card_total.set_value(stats["total"])
            self.card_kev.set_value(stats["kev"])
            self.card_unread.set_value(stats["unread"])
            self.card_high.set_value(stats["high"])

            vulns = self.tools.recent()
            if not vulns:
                empty = QLabel("暂无漏洞数据，等待同步完成后自动刷新")
                empty.setStyleSheet("color:#3d4450; font-size:13px; padding:16px;")
                self.vuln_list.addWidget(empty)
            else:
                for v in vulns[:5]:
                    card = RiskFeedCard(v)
                    card.clicked.connect(lambda d=v: self._on_vuln_click(d))
                    self.vuln_list.addWidget(card)
        except Exception as e:
            logger.error(f"Dashboard load error: {e}")

    def _on_vuln_click(self, data):
        cve_id = data.get("cve_id", "")
        if cve_id:
            self._show_chat()
            self._append_user(f"分析 {cve_id} 的风险和修复建议")
            result = self.tools.cve(cve_id)
            content = str(result) if result else f"未找到 {cve_id}"
            self._history.append({"role": "assistant", "content": content})
            self._stream_assistant(content)

    # ── Style ───────────────────────────────────────────────────────
    def update_config(self, config):
        self.config = config
        self.agent_service = AgentService(lambda: self.config, self.tools)

    def _apply_style(self):
        self.setStyleSheet(AGENT_STYLE)

    # ── Message Helpers ─────────────────────────────────────────────
    def _show_chat(self):
        self.dashboard.hide()
        self.chip_frame.hide()
        self.chat_scroll.show()

    def _append_user(self, text: str):
        msg = ChatMessageWidget("user")
        msg.set_text(text)
        idx = max(0, self.chat_layout.count() - 1)
        self.chat_layout.insertWidget(idx, msg)
        QTimer.singleShot(0, lambda: animate_message_in(msg))
        QTimer.singleShot(30, lambda: smooth_scroll_to_bottom(self.chat_scroll))

    def _append_assistant(self, text: str = "") -> ChatMessageWidget:
        msg = ChatMessageWidget("assistant")
        if text:
            msg.set_text(text)
        idx = max(0, self.chat_layout.count() - 1)
        self.chat_layout.insertWidget(idx, msg)
        QTimer.singleShot(0, lambda: animate_message_in(msg))
        QTimer.singleShot(30, lambda: smooth_scroll_to_bottom(self.chat_scroll))
        return msg

    # ── Streaming ───────────────────────────────────────────────────
    def _stream_assistant(self, text: str):
        self._streaming = True
        msg = self._append_assistant()
        self._current_ai_msg = msg
        renderer = TypewriterRenderer(msg, self)
        self._current_stream = renderer
        renderer.finished.connect(self._on_stream_finished)
        renderer.start()
        renderer.feed(text)
        QTimer.singleShot(max(280, min(1800, len(text) * 4)), renderer.finish)

    # ── Actions ─────────────────────────────────────────────────────
    def _send_prompt(self, prompt: str):
        self._send(prompt)

    def _on_chip(self, label):
        mapping = {"数据库概览": "stats", "最近漏洞": "recent", "高危 Top10": "top_risk"}
        qtype = mapping.get(label)
        if not qtype:
            return
        self._show_chat()
        self._append_user(f"[{label}]")
        if qtype == "stats":
            result = self.tools.stats()
        elif qtype == "recent":
            result = self.tools.recent()
        else:
            result = self.tools.top_risk()
        self._emit_tool_result(result)

    def _send(self, text: str):
        if not text.strip() or self._busy or self._streaming:
            return
        self._show_chat()
        self._append_user(text)
        self._history.append({"role": "user", "content": text})

        db_result = self._try_db(text)
        if db_result is not None:
            self._emit_tool_result(db_result)
            return
        self._call_ai(text)

    def _try_db(self, message):
        normalized = message.strip()
        if not normalized:
            return None

        cve_match = re.search(r"\bCVE[-\s]?(\d{4})[-\s]?(\d{4,})\b", normalized, re.I)
        if cve_match:
            cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
            result = self.tools.cve(cve_id)
            return result if result else f"未在本地数据库中找到 {cve_id}。"

        first_sentence = re.split(r"[。！？\n]", normalized, maxsplit=1)[0]
        short_query = len(normalized) <= 24
        no_context = len(self._history) <= 1

        def starts_with_any(words):
            return any(first_sentence.startswith(w) for w in words)

        allow_tool = short_query or no_context

        if allow_tool and starts_with_any(["统计", "概览", "数据库概览", "当前统计"]):
            return self.tools.stats()

        if allow_tool and starts_with_any(["最近", "最新", "新漏洞", "最近漏洞"]):
            return self.tools.recent()

        if allow_tool and starts_with_any(["高危", "严重", "Top", "TOP", "优先处置"]):
            return self.tools.top_risk()

        search_match = re.match(r"^(搜索|查找|查询)\s+(.+)$", normalized, re.I)
        if search_match and len(search_match.group(2).strip()) >= 2:
            return self.tools.search(search_match.group(2).strip())

        return None

    def _emit_tool_result(self, result):
        if isinstance(result, (dict, list)):
            content = json.dumps(result, ensure_ascii=False, indent=2)
        else:
            content = str(result)
        self._history.append({"role": "assistant", "content": content})
        self._stream_assistant(content)

    def _call_ai(self, msg):
        cfg = getattr(self.config, "agent", None)
        if not cfg or not getattr(cfg, "api_key", ""):
            self._stream_assistant("[!] 未配置 API Key，请在设置 → Agent 配置中设置。")
            return

        self._busy = True
        self._request_id += 1
        request_id = self._request_id

        self.composer.set_generating(True)
        thinking = self._append_assistant("正在思考…")

        self._worker = AgentWorker(self.agent_service, self._history[-10:])
        self._worker.response_ready.connect(
            lambda text, rid=request_id: self._on_ai_ok(rid, thinking, text)
        )
        self._worker.error_occurred.connect(
            lambda err, rid=request_id: self._on_ai_err(rid, thinking, err)
        )
        self._worker.start()

    def _on_ai_ok(self, request_id: int, thinking_widget: ChatMessageWidget, resp: str):
        if request_id != self._request_id:
            return
        thinking_widget.deleteLater()
        self._history.append({"role": "assistant", "content": resp})
        self._stream_assistant(resp)

    def _on_ai_err(self, request_id: int, thinking_widget: ChatMessageWidget, err: str):
        if request_id != self._request_id:
            return
        thinking_widget.deleteLater()
        self._stream_assistant(f"[!] {err}")

    def _on_stream_finished(self):
        self._streaming = False
        self._busy = False
        self._current_stream = None
        self.composer.set_generating(False)

    def _clear(self):
        self._request_id += 1
        if self._current_stream:
            self._current_stream.cancel()
            self._current_stream = None

        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._history.clear()
        self._streaming = False
        self._busy = False
        self._current_ai_msg = None
        self.composer.set_generating(False)
        self.chat_scroll.hide()
        self.dashboard.show()
        self.chip_frame.show()
        self._load_dashboard()
