"""Rcon AI Panel — immersive chat experience for vulnerability intelligence."""

import json
import re
from PySide6.QtCore import Qt, Signal, QThread, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QApplication, QSizePolicy, QGraphicsDropShadowEffect,
    QScrollArea,
)
from loguru import logger

from app.ui.chat_widgets import ChatMessageWidget, ChatComposer, render_markdown
from app.ui.chat_animations import animate_message_in, smooth_scroll_to_bottom, TypewriterRenderer
from app.services.agent_tools import AgentToolService
from app.services.agent_service import AgentService
from app.services.agent_worker import AgentWorker


# ─── Colors (scoped to agent panel) ──────────────────────────────────
C = {
    "bg":        "#0b0d12",
    "bg2":       "#0f1219",
    "surface":   "#111827",
    "surface2":  "#1a2332",
    "card":      "#111827",
    "card_hover":"#1a2536",
    "border":    "#1f2937",
    "border2":   "#243044",
    "blue":      "#3b82f6",
    "blue2":     "#2563eb",
    "blue_dim":  "#1e3a5f",
    "green":     "#22c55e",
    "red":       "#ef4444",
    "orange":    "#f59e0b",
    "text":      "#e5e7eb",
    "text2":     "#9ca3af",
    "text3":     "#4b5563",
    "white":     "#f9fafb",
}

AGENT_STYLE = f"""
QWidget#agentPanel {{
    background: {C['bg']};
    color: {C['text']};
    font-family: "Microsoft YaHei", "Inter", "Segoe UI";
}}

QFrame#agentTopBar {{
    background: rgba(11, 13, 18, 0.96);
    border-bottom: 1px solid {C['border']};
}}

QLabel#agentTitle {{
    color: {C['text']};
    font-size: 15px;
    font-weight: 700;
}}

QLabel#agentSubtitle {{
    color: {C['text2']};
    font-size: 12px;
}}

QWidget#agentPanel QFrame#assistantBubble {{
    background: {C['surface']};
    border: 1px solid {C['border2']};
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
    border-top: 1px solid {C['border']};
}}

QWidget#agentPanel QFrame#composerShell {{
    background: {C['surface']};
    border: 1px solid {C['border2']};
    border-radius: 24px;
}}

QWidget#agentPanel QTextEdit#composerInput {{
    background: transparent;
    color: {C['text']};
    border: none;
    font-size: 14px;
    padding: 2px;
}}

QWidget#agentPanel QPushButton#sendCircle {{
    background: {C['text']};
    color: {C['bg']};
    border: none;
    border-radius: 19px;
    font-size: 18px;
    font-weight: 800;
}}

QWidget#agentPanel QPushButton#sendCircle:hover {{
    background: #dbeafe;
}}

QWidget#agentPanel QPushButton#newBtn {{
    background: {C['surface']};
    color: {C['blue']};
    border: 1px solid {C['border2']};
    border-radius: 14px;
    padding: 5px 16px;
    font-size: 12px;
}}

QWidget#agentPanel QPushButton#newBtn:hover {{
    background: {C['surface2']};
    border-color: {C['blue']};
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
    background: {C['surface']};
    color: {C['text2']};
    border: 1px solid {C['border']};
    border-radius: 16px;
    padding: 7px 16px;
    font-size: 12px;
}}

QWidget#agentPanel QPushButton#chipBtn:hover {{
    background: {C['surface2']};
    color: {C['text']};
    border-color: {C['blue_dim']};
}}

QWidget#agentPanel QScrollArea {{ background: {C['bg']}; border: none; }}
QWidget#agentPanel QScrollBar:vertical {{
    background: {C['bg']}; width: 5px; border: none;
}}
QWidget#agentPanel QScrollBar::handle:vertical {{
    background: {C['border2']}; border-radius: 2px; min-height: 30px;
}}
QWidget#agentPanel QScrollBar::handle:vertical:hover {{ background: {C['text3']}; }}
QWidget#agentPanel QScrollBar::add-line:vertical, QWidget#agentPanel QScrollBar::sub-line:vertical {{ height: 0; }}
"""


# ─── Stat Card (dashboard) ──────────────────────────────────────────
class StatCard(QFrame):
    def __init__(self, label, value, color, parent=None):
        super().__init__(parent)
        self.setFixedSize(140, 80)
        self.setCursor(Qt.PointingHandCursor)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 10)
        layout.setSpacing(4)

        val = QLabel(str(value))
        val.setStyleSheet(f"color:{color}; font-size:26px; font-weight:800; font-family:Consolas;")
        layout.addWidget(val)

        lbl = QLabel(label)
        lbl.setStyleSheet(f"color:{C['text2']}; font-size:12px;")
        layout.addWidget(lbl)

        self.setStyleSheet(f"""
            StatCard {{
                background: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 10px;
            }}
            StatCard:hover {{
                border-color: {C['blue']};
                background: {C['card_hover']};
            }}
        """)

        glow = QGraphicsDropShadowEffect()
        glow.setBlurRadius(8)
        glow.setColor(QColor(color))
        glow.setOffset(0, 0)
        self.setGraphicsEffect(glow)

    def set_value(self, v):
        self.findChild(QLabel).setText(str(v))


# ─── Vuln Card (dashboard) ──────────────────────────────────────────
class VulnCard(QFrame):
    clicked = Signal(dict)

    def __init__(self, data, parent=None):
        super().__init__(parent)
        self._data = data
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(64)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(12)

        cve = QLabel(data.get("cve_id", "N/A"))
        cve.setStyleSheet(f"color:{C['blue']}; font-size:13px; font-weight:bold; font-family:Consolas;")
        cve.setFixedWidth(140)
        layout.addWidget(cve)

        tags_layout = QHBoxLayout()
        tags_layout.setSpacing(4)
        sev = data.get("severity", "").upper()
        if sev in ("CRITICAL", "HIGH"):
            sev_color = C["red"] if sev == "CRITICAL" else C["orange"]
            tag = QLabel(sev)
            tag.setStyleSheet(f"color:{sev_color}; font-size:10px; font-weight:bold; "
                              f"background:{sev_color}18; border:1px solid {sev_color}40; "
                              f"border-radius:4px; padding:1px 5px;")
            tags_layout.addWidget(tag)
        if data.get("is_kev"):
            tag = QLabel("KEV")
            tag.setStyleSheet(f"color:{C['red']}; font-size:10px; font-weight:bold; "
                              f"background:{C['red']}18; border:1px solid {C['red']}40; "
                              f"border-radius:4px; padding:1px 5px;")
            tags_layout.addWidget(tag)
        if data.get("has_poc"):
            tag = QLabel("PoC")
            tag.setStyleSheet(f"color:{C['orange']}; font-size:10px; font-weight:bold; "
                              f"background:{C['orange']}18; border:1px solid {C['orange']}40; "
                              f"border-radius:4px; padding:1px 5px;")
            tags_layout.addWidget(tag)
        tags_layout.addStretch()
        layout.addLayout(tags_layout)

        cvss = data.get("cvss")
        cvss_lbl = QLabel(f"CVSS {cvss:.1f}" if cvss else "CVSS -")
        cvss_lbl.setStyleSheet(f"color:{C['text2']}; font-size:12px; font-family:Consolas;")
        cvss_lbl.setFixedWidth(80)
        layout.addWidget(cvss_lbl)

        score = data.get("score", 0) or 0
        if score >= 80:
            sc_color = C["red"]
        elif score >= 60:
            sc_color = C["orange"]
        elif score >= 40:
            sc_color = C["blue"]
        else:
            sc_color = C["text3"]
        sc_lbl = QLabel(f"{score:.0f}")
        sc_lbl.setStyleSheet(f"color:{sc_color}; font-size:15px; font-weight:bold; font-family:Consolas;")
        sc_lbl.setFixedWidth(36)
        sc_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(sc_lbl)

        title = QLabel(data.get("title", ""))
        title.setStyleSheet(f"color:{C['text2']}; font-size:12px;")
        title.setWordWrap(False)
        layout.addWidget(title, 1)

        self.setStyleSheet(f"""
            VulnCard {{
                background: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
            VulnCard:hover {{
                border-color: {C['blue_dim']};
                background: {C['card_hover']};
            }}
        """)

    def mousePressEvent(self, event):
        self.clicked.emit(self._data)


# ─── Main Agent Panel ───────────────────────────────────────────────
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
        subtitle = QLabel("面向漏洞情报和风险优先级的安全助手")
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
        self.chat_layout.setContentsMargins(0, 24, 0, 24)
        self.chat_layout.setSpacing(4)
        self.chat_layout.addStretch(1)
        self.chat_scroll.setWidget(self.chat_container)
        self.chat_scroll.hide()
        self.content_layout.addWidget(self.chat_scroll)

        root.addWidget(self.content_stack, 1)

        # ── Quick Actions ──────────────────────────────────────────
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

        # ── Composer ───────────────────────────────────────────────
        composer_wrap = QFrame()
        composer_wrap.setObjectName("composerWrap")
        wrap_l = QVBoxLayout(composer_wrap)
        wrap_l.setContentsMargins(120, 12, 120, 18)

        self.composer = ChatComposer()
        self.composer.submitted.connect(self._send)
        wrap_l.addWidget(self.composer)

        root.addWidget(composer_wrap)

    def _build_dashboard(self):
        """Build the dashboard with stat cards and vuln list."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(32, 28, 32, 20)
        layout.setSpacing(24)

        # Header
        header = QHBoxLayout()
        header.setSpacing(12)

        logo = QLabel("R")
        logo.setFixedSize(48, 48)
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet(
            f"color:{C['white']}; background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            f"stop:0 {C['blue2']},stop:1 {C['blue']});"
            f"border-radius:12px; font-size:22px; font-weight:900; font-family:Consolas;"
        )
        header.addWidget(logo)

        info = QVBoxLayout()
        info.setSpacing(2)
        t = QLabel("Rcon")
        t.setStyleSheet(f"color:{C['text']}; font-size:20px; font-weight:700;")
        info.addWidget(t)
        s = QLabel("漏洞情报侦察兵")
        s.setStyleSheet(f"color:{C['text2']}; font-size:13px;")
        info.addWidget(s)
        header.addLayout(info)
        header.addStretch()
        layout.addLayout(header)

        # Stat Cards
        stats_label = QLabel("数据概览")
        stats_label.setStyleSheet(f"color:{C['text2']}; font-size:13px; font-weight:600; margin-top:4px;")
        layout.addWidget(stats_label)

        self.stats_grid = QHBoxLayout()
        self.stats_grid.setSpacing(14)

        self.card_total = StatCard("总漏洞", "—", C["blue"])
        self.card_kev = StatCard("KEV 命中", "—", C["red"])
        self.card_unread = StatCard("未读", "—", C["orange"])
        self.card_high = StatCard("高危 ≥80", "—", C["red"])

        for card in [self.card_total, self.card_kev, self.card_unread, self.card_high]:
            self.stats_grid.addWidget(card)
        self.stats_grid.addStretch()
        layout.addLayout(self.stats_grid)

        # Vuln List
        vuln_header = QHBoxLayout()
        vh_label = QLabel("最近漏洞")
        vh_label.setStyleSheet(f"color:{C['text2']}; font-size:13px; font-weight:600;")
        vuln_header.addWidget(vh_label)
        vuln_header.addStretch()

        self.btn_more = QPushButton("查看全部 →")
        self.btn_more.setObjectName("linkBtn")
        self.btn_more.setCursor(Qt.PointingHandCursor)
        self.btn_more.clicked.connect(lambda: self._on_chip("最近漏洞"))
        vuln_header.addWidget(self.btn_more)
        layout.addLayout(vuln_header)

        self.vuln_list = QVBoxLayout()
        self.vuln_list.setSpacing(6)
        layout.addLayout(self.vuln_list)

        layout.addStretch()
        scroll.setWidget(page)
        return scroll

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
                for v in vulns:
                        card = VulnCard(v)
                        card.clicked.connect(lambda d=v: self._on_vuln_click(d))
                        self.vuln_list.addWidget(card)
        except Exception as e:
            logger.error(f"Dashboard load error: {e}")

    def _on_vuln_click(self, data):
        cve_id = data.get("cve_id", "")
        if cve_id:
            self._show_chat()
            self._append_user(cve_id)
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

    # ── Streaming (single-widget update, no delete/recreate) ────────
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

    def _on_stream_finished(self):
        self._streaming = False
        self._current_stream = None

    # ── Actions ─────────────────────────────────────────────────────
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
        if not text.strip() or self._busy:
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

        # CVE query — always highest priority, any position
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
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._history.clear()
        self._streaming = False
        self._busy = False
        self._current_stream = None
        self._current_ai_msg = None
        self.chat_scroll.hide()
        self.dashboard.show()
        self._load_dashboard()
        self._load_dashboard()
