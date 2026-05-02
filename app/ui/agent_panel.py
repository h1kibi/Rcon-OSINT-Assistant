"""Rcon AI Panel — pixel-hacker terminal workspace with persistent multi-session chat."""

import json
import re
from PySide6.QtCore import Qt, Signal, QThread, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QApplication, QSizePolicy, QGraphicsDropShadowEffect,
    QScrollArea, QGridLayout, QInputDialog, QMessageBox, QMenu,
)
from loguru import logger

from app.ui.chat_widgets import ChatMessageWidget, ChatComposer, render_markdown
from app.ui.chat_animations import animate_message_in, smooth_scroll_to_bottom, TypewriterRenderer
from app.services.agent_tools import AgentToolService
from app.services.agent_service import AgentService
from app.services.agent_worker import AgentWorker
from app.ui.fonts import pixel_font, mono_font, text_font
from app.db import repositories as repo

CENTER_MAX_WIDTH = 1320
COMPOSER_MAX_WIDTH = 1180


AGENT_STYLE = """
QWidget#agentPanel {
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 #050805, stop:0.55 #040704, stop:1 #071007
    );
    color: #d6ffd6;
}

QFrame#sessionBar {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #040704, stop:0.5 #061006, stop:1 #040704
    );
    border-bottom: 1px solid #15451f;
}

QScrollArea#sessionScroll {
    background: transparent;
    border: none;
}

QPushButton#sessionTab {
    background: #071007;
    color: #77d982;
    border: 1px solid #15451f;
    border-radius: 4px;
    padding: 5px 12px;
    text-align: left;
}

QPushButton#sessionTab:hover {
    color: #d6ffd6;
    border: 1px solid #39ff14;
    background: #0a140a;
}

QPushButton#sessionTab:checked {
    color: #39ff14;
    border: 1px solid #39ff14;
    background: #0d180d;
}

QPushButton#newSessionBtn {
    background: #071007;
    color: #39ff14;
    border: 1px solid #39ff14;
    border-radius: 4px;
    padding: 6px 18px;
}

QPushButton#newSessionBtn:hover {
    background: #102010;
}

QWidget#agentPanel QFrame#assistantBubble {
    background: #081008;
    border: 1px solid #143d1f;
    border-radius: 4px;
}

QWidget#agentPanel QFrame#userBubble {
    background: #102010;
    border: 1px solid #2aff66;
    border-radius: 4px;
}

QWidget#agentPanel QLabel#userAvatar {
    color: #051005;
    background: #39ff14;
    border: 1px solid #39ff14;
    border-radius: 4px;
}

QWidget#agentPanel QLabel#assistantAvatar {
    color: #39ff14;
    background: #0d180d;
    border: 1px solid #1ed760;
    border-radius: 4px;
}

QWidget#agentPanel QTextBrowser#messageBody {
    background: transparent;
    color: #d6ffd6;
    border: none;
    font-size: 14px;
    line-height: 160%;
}

QFrame#dashboardShell {
    background: transparent;
}

QFrame#heroCard {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 #071007, stop:0.55 #081008, stop:1 #0c160c
    );
    border: 1px solid #1b5e20;
    border-radius: 6px;
}

QLabel#heroTitle {
    color: #d6ffd6;
}

QLabel#heroSubtitle {
    color: #9cd8a7;
}

QLabel#heroPrompt {
    color: #39ff14;
}

QLabel#sectionTitle {
    color: #39ff14;
    font-size: 12px;
    font-weight: 600;
}

QPushButton#linkBtn {
    background: transparent;
    color: #7dff7d;
    border: 1px solid #16521f;
    border-radius: 3px;
    padding: 4px 10px;
}

QPushButton#linkBtn:hover {
    color: #39ff14;
    border: 1px solid #39ff14;
}

QFrame#metricPill,
QFrame#promptCard,
QFrame#riskFeedCard {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 #071007, stop:0.55 #081008, stop:1 #0c160c
    );
    border: 1px solid #16521f;
    border-radius: 4px;
}

QFrame#promptCard:hover,
QFrame#riskFeedCard:hover {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 #0a140a, stop:0.6 #0c180c, stop:1 #0f1b0f
    );
    border: 1px solid #39ff14;
}

QLabel#metricValue {
    color: #39ff14;
    font-size: 20px;
    font-weight: 900;
}

QLabel#metricLabel {
    color: #78b985;
    font-size: 11px;
}

QLabel#promptTitle {
    color: #d6ffd6;
    font-size: 13px;
    font-weight: 700;
}

QLabel#promptDesc {
    color: #8dcf98;
    font-size: 12px;
}

QLabel#promptBadge {
    color: #39ff14;
    background: #0d180d;
    border: 1px solid #1ed760;
    border-radius: 2px;
    padding: 2px 8px;
    font-size: 10px;
}

QLabel#riskCve {
    color: #7dff7d;
    font-size: 11px;
    font-weight: 800;
}

QLabel#riskTitle {
    color: #cfe9d2;
    font-size: 12px;
}

QLabel#riskMeta {
    color: #6fa57a;
    font-size: 11px;
}

QLabel#riskScore {
    color: #39ff14;
    background: #0c160c;
    border: 1px solid #1ed760;
    border-radius: 4px;
    font-size: 18px;
    font-weight: 900;
}

QFrame#chipWrap {
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 #050805, stop:1 #061006
    );
    border-top: 1px solid #102610;
}

QFrame#chipInner {
    background: transparent;
}

QPushButton#chipBtn {
    background: #071007;
    color: #8dcf98;
    border: 1px solid #16521f;
    border-radius: 4px;
    padding: 7px 16px;
}

QPushButton#chipBtn:hover {
    color: #39ff14;
    background: #0a140a;
    border: 1px solid #39ff14;
}

QFrame#composerWrap {
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 #050805, stop:1 #071007
    );
    border-top: 1px solid #102610;
}

QFrame#composerShell {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 #071007, stop:0.65 #081008, stop:1 #0d180d
    );
    border: 1px solid #1b5e20;
    border-radius: 4px;
}

QFrame#composerShell[focused="true"] {
    background: #0a120a;
    border: 1px solid #39ff14;
}

QTextEdit#composerInput {
    background: transparent;
    color: #d6ffd6;
    border: none;
    font-size: 13px;
    padding: 2px;
}

QPushButton#sendCircle {
    background: #0d180d;
    color: #39ff14;
    border: 1px solid #1ed760;
    border-radius: 4px;
    font-size: 14px;
    font-weight: 900;
}

QPushButton#sendCircle:hover {
    background: #102010;
    border: 1px solid #39ff14;
}

QScrollBar:vertical {
    background: #050805;
    width: 8px;
}

QScrollBar::handle:vertical {
    background: #1ed760;
    border-radius: 3px;
    min-height: 36px;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0px;
}
"""


# ─── Session Tab Widget ───────────────────────────────────────────────
class SessionTab(QPushButton):
    rename_requested = Signal(int)
    delete_requested = Signal(int)

    def __init__(self, session_id: int, title: str, parent=None):
        super().__init__(title, parent)
        self.session_id = session_id
        self.setObjectName("sessionTab")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumWidth(132)
        self.setMaximumWidth(220)
        self.setFixedHeight(34)
        self.setFont(pixel_font(9, bold=True))

    def mouseDoubleClickEvent(self, event):
        self.rename_requested.emit(self.session_id)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        rename_action = menu.addAction("RENAME")
        delete_action = menu.addAction("DELETE")
        action = menu.exec(event.globalPos())
        if action == rename_action:
            self.rename_requested.emit(self.session_id)
        elif action == delete_action:
            self.delete_requested.emit(self.session_id)


# ─── Metric Pill ──────────────────────────────────────────────────────
class MetricPill(QFrame):
    def __init__(self, label: str, value: str, accent: str = "#39ff14", parent=None):
        super().__init__(parent)
        self.setObjectName("metricPill")
        self.setMinimumHeight(78)
        self.setMaximumHeight(92)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)
        self.value_label = QLabel(str(value))
        self.value_label.setObjectName("metricValue")
        self.value_label.setFont(pixel_font(16, bold=True))
        self.value_label.setStyleSheet(f"color: {accent};")
        layout.addWidget(self.value_label)
        lbl = QLabel(label)
        lbl.setObjectName("metricLabel")
        lbl.setFont(mono_font(10))
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
        self.setMinimumHeight(96)
        self.setMaximumHeight(112)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(8)
        header = QHBoxLayout()
        header.setSpacing(8)
        head = QLabel(title)
        head.setObjectName("promptTitle")
        head.setFont(pixel_font(10, bold=True))
        header.addWidget(head)
        header.addStretch(1)
        if badge:
            badge_label = QLabel(badge)
            badge_label.setObjectName("promptBadge")
            badge_label.setAlignment(Qt.AlignCenter)
            badge_label.setFixedHeight(22)
            badge_label.setMinimumWidth(42)
            badge_label.setFont(pixel_font(8, bold=True))
            header.addWidget(badge_label)
        layout.addLayout(header)
        body = QLabel(desc)
        body.setObjectName("promptDesc")
        body.setFont(mono_font(10))
        body.setWordWrap(True)
        layout.addWidget(body)
        layout.addStretch(1)

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
        self.setMinimumHeight(78)
        self.setMaximumHeight(92)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)
        left = QVBoxLayout()
        left.setSpacing(4)
        cve = QLabel(data.get("cve_id", "N/A"))
        cve.setObjectName("riskCve")
        cve.setFont(pixel_font(9, bold=True))
        left.addWidget(cve)
        title = QLabel(data.get("title", ""))
        title.setObjectName("riskTitle")
        title.setFont(mono_font(10))
        title.setWordWrap(True)
        title.setMaximumHeight(34)
        left.addWidget(title)
        meta = QLabel(self._meta_text(data))
        meta.setObjectName("riskMeta")
        meta.setFont(mono_font(9))
        left.addWidget(meta)
        layout.addLayout(left, 1)
        score = int(data.get("score", 0) or 0)
        badge = QLabel(f"{score:03d}")
        badge.setObjectName("riskScore")
        badge.setAlignment(Qt.AlignCenter)
        badge.setFixedSize(50, 50)
        badge.setFont(pixel_font(12, bold=True))
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
        return " · ".join(parts) or "NO_TAGS"

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
        self._current_history: list[dict] = []
        self._current_vuln = None
        self._streaming = False
        self._current_stream: TypewriterRenderer | None = None
        self._current_ai_msg: ChatMessageWidget | None = None
        self._busy = False
        self._request_id = 0
        self._sessions: list = []
        self._current_session_id: int | None = None

        self.tools = AgentToolService(db_session_factory)
        self.agent_service = AgentService(lambda: self.config, self.tools)

        self._build_ui()
        self._apply_style()
        self._load_sessions()

    def set_current_vuln(self, v):
        self._current_vuln = v

    # ── Session Management ───────────────────────────────────────────
    def _load_sessions(self):
        db = self.db()
        try:
            sessions = repo.list_agent_sessions(db, limit=30)
            if not sessions:
                first = repo.create_agent_session(db)
                sessions = [first]
            self._sessions = sessions
            self._current_session_id = sessions[0].id
            repo.touch_agent_session(db, self._current_session_id)
        finally:
            db.close()
        self._render_session_tabs()
        self._load_current_session()

    def _refresh_sessions(self):
        db = self.db()
        try:
            self._sessions = repo.list_agent_sessions(db, limit=30)
        finally:
            db.close()

    def _new_session(self):
        if self._busy or self._streaming:
            return
        db = self.db()
        try:
            s = repo.create_agent_session(db)
        finally:
            db.close()
        self._sessions.append(s)
        self._switch_session(s.id)

    def _switch_session(self, session_id: int):
        if self._busy or self._streaming:
            return
        if session_id == self._current_session_id:
            return
        self._request_id += 1
        if self._current_stream:
            self._current_stream.cancel()
            self._current_stream = None
        self._current_session_id = session_id
        db = self.db()
        try:
            repo.touch_agent_session(db, session_id)
        finally:
            db.close()
        self._render_session_tabs()
        self._load_current_session()

    def _render_session_tabs(self):
        while self.session_tabs_layout.count():
            item = self.session_tabs_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        for s in self._sessions:
            tab = SessionTab(s.id, s.title)
            tab.setChecked(s.id == self._current_session_id)
            tab.clicked.connect(lambda _, sid=s.id: self._switch_session(sid))
            tab.rename_requested.connect(self._rename_session_dialog)
            tab.delete_requested.connect(self._delete_session)
            self.session_tabs_layout.addWidget(tab)
        self.session_tabs_layout.addStretch(1)

    def _rename_session_dialog(self, session_id: int):
        s = next((x for x in self._sessions if x.id == session_id), None)
        if not s:
            return
        title, ok = QInputDialog.getText(self, "RENAME_SESSION", "New session title:", text=s.title)
        if not ok:
            return
        title = title.strip()
        if not title:
            return
        db = self.db()
        try:
            repo.rename_agent_session(db, session_id, title)
        finally:
            db.close()
        self._refresh_sessions()
        self._render_session_tabs()

    def _delete_session(self, session_id: int):
        if len(self._sessions) <= 1:
            QMessageBox.information(self, "DELETE_SESSION", "至少保留一个会话。")
            return
        s = next((x for x in self._sessions if x.id == session_id), None)
        ret = QMessageBox.question(
            self, "DELETE_SESSION",
            f"Delete session [{s.title if s else 'SESSION'}]?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ret != QMessageBox.Yes:
            return
        db = self.db()
        try:
            repo.soft_delete_agent_session(db, session_id)
        finally:
            db.close()
        was_current = session_id == self._current_session_id
        self._refresh_sessions()
        if was_current:
            if self._sessions:
                self._switch_session(self._sessions[0].id)
            else:
                self._new_session()
        else:
            self._render_session_tabs()

    def _clear_chat_widgets(self):
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _load_current_session(self):
        self._clear_chat_widgets()
        db = self.db()
        try:
            messages = repo.get_agent_messages(db, self._current_session_id)
        finally:
            db.close()
        self._current_history = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant", "tool", "error")
        ]
        if not messages:
            self.dashboard.show()
            self.chat_scroll.hide()
            self.chip_frame.show()
            self._load_dashboard()
            return
        self.dashboard.hide()
        self.chat_scroll.show()
        self.chip_frame.hide()
        for m in messages:
            display_role = "assistant" if m.role in ("assistant", "tool", "error") else "user"
            self._append_message(display_role, m.content, animate=False)
        QTimer.singleShot(20, lambda: smooth_scroll_to_bottom(self.chat_scroll, duration=80))

    def _maybe_auto_title(self, text: str):
        s = next((x for x in self._sessions if x.id == self._current_session_id), None)
        if not s or not s.title.startswith("SESSION_"):
            return
        title = " ".join(text.split())
        title = title.replace("\n", " ")
        title = title[:24] + "..." if len(title) > 24 else title
        db = self.db()
        try:
            repo.rename_agent_session(db, s.id, title)
        finally:
            db.close()
        self._refresh_sessions()
        self._render_session_tabs()

    # ── Build UI ────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_session_bar())

        self.content_stack = QWidget()
        self.content_layout = QVBoxLayout(self.content_stack)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)

        self.dashboard = self._build_dashboard()
        self.content_layout.addWidget(self.dashboard)

        self.chat_scroll = QScrollArea()
        self.chat_scroll.setWidgetResizable(True)
        self.chat_scroll.setFrameShape(QFrame.NoFrame)
        self.chat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.chat_container = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setContentsMargins(0, 36, 0, 36)
        self.chat_layout.setSpacing(8)
        self.chat_layout.addStretch(1)
        self.chat_scroll.setWidget(self.chat_container)
        self.chat_scroll.hide()
        self.content_layout.addWidget(self.chat_scroll)

        root.addWidget(self.content_stack, 1)

        chip_wrap = QFrame()
        chip_wrap.setObjectName("chipWrap")
        outer = QHBoxLayout(chip_wrap)
        outer.setContentsMargins(20, 8, 20, 8)
        outer.setSpacing(0)
        chip_inner = QFrame()
        chip_inner.setObjectName("chipInner")
        chip_inner.setMaximumWidth(COMPOSER_MAX_WIDTH)
        chip_l = QHBoxLayout(chip_inner)
        chip_l.setContentsMargins(0, 0, 0, 0)
        chip_l.setSpacing(10)
        for text, label in [("▣", "数据库概览"), ("◉", "最近漏洞"), ("▲", "高危 Top10")]:
            btn = QPushButton(f"{text}  {label}")
            btn.setObjectName("chipBtn")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setFont(mono_font(10))
            btn.clicked.connect(lambda _, l=label: self._on_chip(l))
            chip_l.addWidget(btn)
        chip_l.addStretch(1)
        outer.addStretch(1)
        outer.addWidget(chip_inner, 1)
        outer.addStretch(1)
        self.chip_frame = chip_wrap
        root.addWidget(self.chip_frame)

        composer_wrap = QFrame()
        composer_wrap.setObjectName("composerWrap")
        wrap_l = QHBoxLayout(composer_wrap)
        wrap_l.setContentsMargins(20, 10, 20, 18)
        wrap_l.setSpacing(0)
        self.composer = ChatComposer()
        self.composer.setMaximumWidth(COMPOSER_MAX_WIDTH)
        self.composer.submitted.connect(self._send)
        self.composer.input.setPlaceholderText("> query CVE / KEV / EPSS or generate fix priority...")
        self.composer.input.setFont(mono_font(11))
        self.composer.send_btn.setText(">>")
        self.composer.send_btn.setFixedSize(46, 34)
        self.composer.send_btn.setFont(pixel_font(10, bold=True))
        wrap_l.addStretch(1)
        wrap_l.addWidget(self.composer, 1)
        wrap_l.addStretch(1)
        root.addWidget(composer_wrap)

    def _build_session_bar(self):
        bar = QFrame()
        bar.setObjectName("sessionBar")
        bar.setFixedHeight(54)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(18, 8, 18, 8)
        layout.setSpacing(10)
        self.session_scroll = QScrollArea()
        self.session_scroll.setObjectName("sessionScroll")
        self.session_scroll.setWidgetResizable(True)
        self.session_scroll.setFrameShape(QFrame.NoFrame)
        self.session_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.session_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.session_tabs_container = QWidget()
        self.session_tabs_layout = QHBoxLayout(self.session_tabs_container)
        self.session_tabs_layout.setContentsMargins(0, 0, 0, 0)
        self.session_tabs_layout.setSpacing(8)
        self.session_tabs_layout.addStretch(1)
        self.session_scroll.setWidget(self.session_tabs_container)
        layout.addWidget(self.session_scroll, 1)
        self.btn_new = QPushButton("+ NEW")
        self.btn_new.setObjectName("newSessionBtn")
        self.btn_new.setCursor(Qt.PointingHandCursor)
        self.btn_new.setFont(pixel_font(9, bold=True))
        self.btn_new.clicked.connect(self._new_session)
        layout.addWidget(self.btn_new)
        return bar

    def _build_hero_card(self):
        hero = QFrame()
        hero.setObjectName("heroCard")
        hero.setMinimumHeight(140)
        hero.setMaximumHeight(160)
        layout = QVBoxLayout(hero)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(9)
        title = QLabel("RCON_AI")
        title.setObjectName("heroTitle")
        title.setFont(pixel_font(22, bold=True))
        layout.addWidget(title)
        sub = QLabel("LOCAL VULN INTEL ASSISTANT")
        sub.setObjectName("heroSubtitle")
        sub.setFont(mono_font(11))
        layout.addWidget(sub)
        prompt = QLabel("> query CVE / KEV / EPSS / PATCH_PRIORITY")
        prompt.setObjectName("heroPrompt")
        prompt.setFont(mono_font(11, bold=True))
        layout.addWidget(prompt)
        layout.addStretch(1)
        return hero

    def _build_dashboard(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        page = QWidget()
        page_layout = QHBoxLayout(page)
        page_layout.setContentsMargins(20, 28, 20, 24)
        page_layout.setSpacing(0)
        shell = QFrame()
        shell.setObjectName("dashboardShell")
        shell.setMaximumWidth(CENTER_MAX_WIDTH)
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(16)
        main_row = QHBoxLayout()
        main_row.setSpacing(18)
        left_col = QVBoxLayout()
        left_col.setSpacing(14)
        hero = self._build_hero_card()
        left_col.addWidget(hero)
        metrics = QHBoxLayout()
        metrics.setSpacing(10)
        self.card_total = MetricPill("总漏洞", "—", "#39ff14")
        self.card_kev = MetricPill("KEV 命中", "—", "#39ff14")
        self.card_unread = MetricPill("未读", "—", "#39ff14")
        self.card_high = MetricPill("高危 ≥80", "—", "#39ff14")
        for card in [self.card_total, self.card_kev, self.card_unread, self.card_high]:
            metrics.addWidget(card)
        left_col.addLayout(metrics)
        prompt_grid = QGridLayout()
        prompt_grid.setSpacing(12)
        prompts = [
            ("今日优先处置", "汇总当前最值得优先修复的风险。",
             "根据本地漏洞数据库，总结当前最值得优先处置的漏洞，并说明排序原因。", "P1"),
            ("KEV 命中分析", "查看存在在野利用证据的关键漏洞。", "高危 Top10", "KEV"),
            ("最近新增漏洞", "快速浏览最近同步进来的漏洞情报。", "最近漏洞", "NEW"),
            ("修复优先级清单", "生成面向安全运营的处置建议。",
             "请根据当前漏洞库生成一份修复优先级清单，按紧急程度分组，并给出修复建议。", "FIX"),
        ]
        for i, (p_title, desc, prompt, badge) in enumerate(prompts):
            card = PromptCard(p_title, desc, prompt, badge)
            card.clicked.connect(self._send_prompt)
            prompt_grid.addWidget(card, i // 2, i % 2)
        left_col.addLayout(prompt_grid)
        left_col.addStretch(1)
        right_col = QVBoxLayout()
        right_col.setSpacing(12)
        right_header = QHBoxLayout()
        feed_title = QLabel("RECENT_RISK_FEED")
        feed_title.setObjectName("sectionTitle")
        feed_title.setFont(pixel_font(11, bold=True))
        right_header.addWidget(feed_title)
        right_header.addStretch()
        self.btn_more = QPushButton("VIEW_ALL")
        self.btn_more.setObjectName("linkBtn")
        self.btn_more.setFont(pixel_font(9, bold=True))
        self.btn_more.clicked.connect(lambda: self._on_chip("最近漏洞"))
        right_header.addWidget(self.btn_more)
        right_col.addLayout(right_header)
        self.vuln_list = QVBoxLayout()
        self.vuln_list.setSpacing(8)
        right_col.addLayout(self.vuln_list)
        right_col.addStretch(1)
        main_row.addLayout(left_col, 7)
        main_row.addLayout(right_col, 5)
        shell_layout.addLayout(main_row)
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
                for v in vulns[:6]:
                    card = RiskFeedCard(v)
                    card.clicked.connect(lambda d=v: self._on_vuln_click(d))
                    self.vuln_list.addWidget(card)
        except Exception as e:
            logger.error(f"Dashboard load error: {e}")

    def _on_vuln_click(self, data):
        cve_id = data.get("cve_id", "")
        if cve_id:
            self._show_chat()
            self._append_user_text(f"分析 {cve_id} 的风险和修复建议")
            result = self.tools.cve(cve_id)
            content = str(result) if result else f"未找到 {cve_id}"
            self._persist_and_stream("tool", content)

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
        self.chip_frame.hide()

    def _append_message(self, role: str, text: str, animate: bool = True) -> ChatMessageWidget:
        msg = ChatMessageWidget(role)
        msg.set_text(text)
        idx = max(0, self.chat_layout.count() - 1)
        self.chat_layout.insertWidget(idx, msg)
        if animate:
            QTimer.singleShot(0, lambda: animate_message_in(msg))
        QTimer.singleShot(30, lambda: smooth_scroll_to_bottom(self.chat_scroll))
        return msg

    def _append_user_text(self, text: str):
        self._append_message("user", text)

    # ── Persist + Stream ────────────────────────────────────────────
    def _persist_and_stream(self, role: str, content: str, model: str = "", error: str = ""):
        db = self.db()
        try:
            repo.append_agent_message(db, self._current_session_id, role, content, model=model, error=error)
        finally:
            db.close()
        history_role = "assistant" if role in ("tool", "error") else role
        self._current_history.append({"role": history_role, "content": content})
        self._stream_assistant(content)

    def _stream_assistant(self, text: str):
        self._streaming = True
        msg = self._append_message("assistant", "")
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
        self._append_user_text(f"[{label}]")
        self._persist_and_stream("user", f"[{label}]")
        if qtype == "stats":
            result = self.tools.stats()
        elif qtype == "recent":
            result = self.tools.recent()
        else:
            result = self.tools.top_risk()
        content = json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, (dict, list)) else str(result)
        self._persist_and_stream("tool", content)

    def _send(self, text: str):
        text = text.strip()
        if not text or self._busy or self._streaming:
            return
        self._show_chat()
        self._persist_and_stream("user", text)
        self._append_user_text(text)
        self._maybe_auto_title(text)
        db_result = self._try_db(text)
        if db_result is not None:
            content = json.dumps(db_result, ensure_ascii=False, indent=2) if isinstance(db_result, (dict, list)) else str(db_result)
            self._persist_and_stream("tool", content)
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
        no_context = len(self._current_history) <= 1
        allow_tool = short_query or no_context
        def starts_with_any(words):
            return any(first_sentence.startswith(w) for w in words)
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

    def _call_ai(self, text: str):
        cfg = getattr(self.config, "agent", None)
        if not cfg or not getattr(cfg, "api_key", ""):
            self._persist_and_stream("error", "[!] 未配置 API Key，请在设置 → Agent 配置中设置。")
            return
        self._busy = True
        self._request_id += 1
        request_id = self._request_id
        session_id = self._current_session_id
        self.composer.set_generating(True)
        thinking = self._append_message("assistant", "正在思考…")
        self._worker = AgentWorker(self.agent_service, self._current_history[-10:])
        self._worker.response_ready.connect(
            lambda text, rid=request_id, sid=session_id: self._on_ai_ok(rid, sid, thinking, text)
        )
        self._worker.error_occurred.connect(
            lambda err, rid=request_id, sid=session_id: self._on_ai_err(rid, sid, thinking, err)
        )
        self._worker.start()

    def _on_ai_ok(self, request_id: int, session_id: int, thinking_widget, text: str):
        if request_id != self._request_id or session_id != self._current_session_id:
            return
        thinking_widget.deleteLater()
        model = getattr(getattr(self.config, "agent", None), "model", "")
        db = self.db()
        try:
            repo.append_agent_message(db, session_id, "assistant", text, model=model)
        finally:
            db.close()
        self._current_history.append({"role": "assistant", "content": text})
        self._stream_assistant(text)

    def _on_ai_err(self, request_id: int, session_id: int, thinking_widget, err: str):
        if request_id != self._request_id or session_id != self._current_session_id:
            return
        thinking_widget.deleteLater()
        content = f"[!] {err}"
        db = self.db()
        try:
            repo.append_agent_message(db, session_id, "error", content, error=err)
        finally:
            db.close()
        self._current_history.append({"role": "assistant", "content": content})
        self._stream_assistant(content)

    def _on_stream_finished(self):
        self._streaming = False
        self._busy = False
        self._current_stream = None
        self.composer.set_generating(False)
