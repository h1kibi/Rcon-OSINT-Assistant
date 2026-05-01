import re
from PySide6.QtCore import Qt, Signal, QThread, QTimer, QObject
from PySide6.QtGui import QColor, QPainter, QPen, QBrush, QFont, QPainterPath
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QFrame, QLineEdit, QApplication, QSizePolicy,
    QGraphicsDropShadowEffect, QScrollArea, QGridLayout
)
from loguru import logger


# ─── Worker ───────────────────────────────────────────────────────
class AgentWorker(QThread):
    response_ready = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, protocol, api_key, base_url, model, system_prompt, messages, max_tokens=2000):
        super().__init__()
        self.protocol = protocol
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.system_prompt = system_prompt
        self.messages = messages
        self.max_tokens = max_tokens

    def run(self):
        try:
            import httpx
            if "Anthropic" in self.protocol:
                self._call_anthropic()
            else:
                self._call_openai()
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _call_openai(self):
        import httpx
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        all_msgs = [{"role": "system", "content": self.system_prompt}] + self.messages
        data = {"model": self.model, "messages": all_msgs, "max_tokens": self.max_tokens, "temperature": 0.7}
        resp = httpx.post(f"{self.base_url}/chat/completions", headers=headers, json=data, timeout=120.0)
        if resp.status_code != 200:
            try:
                detail = resp.json().get("error", {}).get("message", resp.text[:200])
            except:
                detail = resp.text[:200]
            raise Exception(f"API {resp.status_code}: {detail}")
        result = resp.json()
        if "choices" not in result:
            raise Exception(f"响应格式异常: {str(result)[:200]}")
        self.response_ready.emit(result["choices"][0]["message"]["content"])

    def _call_anthropic(self):
        import httpx
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        data = {"model": self.model, "max_tokens": self.max_tokens, "system": self.system_prompt, "messages": self.messages}
        resp = httpx.post(f"{self.base_url}/messages", headers=headers, json=data, timeout=120.0)
        if resp.status_code != 200:
            try:
                detail = resp.json().get("error", {}).get("message", resp.text[:200])
            except:
                detail = resp.text[:200]
            raise Exception(f"API {resp.status_code}: {detail}")
        self.response_ready.emit(resp.json()["content"][0]["text"])


# ─── Stream Animator ──────────────────────────────────────────────
class StreamAnimator(QObject):
    chunk_ready = Signal(str)
    finished = Signal()

    def __init__(self):
        super().__init__()
        self._text = ""
        self._idx = 0
        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)

    def start(self, text, speed_ms=8):
        self._text = text
        self._idx = 0
        self._timer.start(speed_ms)

    def _tick(self):
        if self._idx < len(self._text):
            end = min(self._idx + 3, len(self._text))
            self.chunk_ready.emit(self._text[self._idx:end])
            self._idx = end
        else:
            self._timer.stop()
            self.finished.emit()

    def stop(self):
        self._timer.stop()
        self._text = ""
        self._idx = 0


# ─── Colors ───────────────────────────────────────────────────────
C = {
    "bg":        "#0b0f19",
    "bg2":       "#0f1520",
    "surface":   "#131a28",
    "surface2":  "#182030",
    "card":      "#141c2b",
    "card_hover":"#1a2536",
    "border":    "#1c2940",
    "border2":   "#253550",
    "blue":      "#3b82f6",
    "blue2":     "#2563eb",
    "blue_dim":  "#1e3a5f",
    "green":     "#22c55e",
    "red":       "#ef4444",
    "orange":    "#f59e0b",
    "text":      "#e2e8f0",
    "text2":     "#94a3b8",
    "text3":     "#475569",
    "white":     "#ffffff",
}


# ─── Database Query ───────────────────────────────────────────────
def query_database(db, query_type, params=None):
    from app.db.models import Vulnerability
    from sqlmodel import select, func
    session = db()
    try:
        if query_type == "stats":
            t = session.exec(select(func.count(Vulnerability.id))).one()
            k = session.exec(select(func.count(Vulnerability.id)).where(Vulnerability.is_kev == True)).one()
            u = session.exec(select(func.count(Vulnerability.id)).where(Vulnerability.status == "unread")).one()
            h = session.exec(select(func.count(Vulnerability.id)).where(Vulnerability.action_value_score >= 80)).one()
            return {"total": t, "kev": k, "unread": u, "high": h}
        elif query_type == "recent":
            vulns = session.exec(select(Vulnerability).order_by(Vulnerability.published_at.desc()).limit(8)).all()
            return [{
                "cve_id": v.cve_id, "title": v.title[:60], "severity": v.severity,
                "cvss": v.cvss_score, "score": v.action_value_score,
                "is_kev": v.is_kev, "has_poc": v.has_poc_signal,
            } for v in vulns]
        elif query_type == "top_risk":
            vulns = session.exec(select(Vulnerability).order_by(Vulnerability.action_value_score.desc()).limit(8)).all()
            return [{
                "cve_id": v.cve_id, "title": v.title[:60], "severity": v.severity,
                "cvss": v.cvss_score, "score": v.action_value_score,
                "is_kev": v.is_kev, "has_poc": v.has_poc_signal,
            } for v in vulns]
        elif query_type == "search":
            kw = params.get("keyword", "") if params else ""
            vulns = session.exec(select(Vulnerability).where(
                (Vulnerability.cve_id.contains(kw)) | (Vulnerability.title.contains(kw))
            ).limit(10)).all()
            if not vulns:
                return f"未找到 '{kw}'"
            lines = [f"搜索 '{kw}' ({len(vulns)} 条):"]
            for v in vulns:
                lines.append(f"{v.cve_id}  评分:{v.action_value_score:.0f}\n{v.title[:50]}")
            return "\n---\n".join(lines)
        elif query_type == "cve":
            cve_id = params.get("cve_id", "") if params else ""
            vuln = session.exec(select(Vulnerability).where(Vulnerability.cve_id == cve_id)).first()
            if not vuln:
                return f"未找到 {cve_id}"
            return (f"{vuln.cve_id}\n{vuln.title}\n\n等级: {vuln.severity}  CVSS: {vuln.cvss_score or '-'}  EPSS: {vuln.epss_score or '-'}\n"
                    f"KEV: {'是' if vuln.is_kev else '否'}  PoC: {'是' if vuln.has_poc_signal else '否'}  评分: {vuln.action_value_score:.0f}/100\n\n{vuln.description[:500]}")
        return "未知查询"
    except Exception as e:
        return f"错误: {e}"
    finally:
        session.close()


# ─── Stat Card Widget ─────────────────────────────────────────────
class StatCard(QFrame):
    def __init__(self, label, value, color, parent=None):
        super().__init__(parent)
        self.setFixedSize(140, 80)
        self.setCursor(Qt.PointingHandCursor)
        self._color = color

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 10)
        layout.setSpacing(4)

        val = QLabel(str(value))
        val.setObjectName("statValue")
        val.setStyleSheet(f"color:{color}; font-size:26px; font-weight:800; font-family:Consolas;")
        layout.addWidget(val)

        lbl = QLabel(label)
        lbl.setObjectName("statLabel")
        lbl.setStyleSheet(f"color:{C['text2']}; font-size:12px; font-family:'Microsoft YaHei';")
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
        glow.setBlurRadius(16)
        glow.setColor(QColor(color))
        glow.setOffset(0, 0)
        # Only show subtle glow
        glow.setBlurRadius(8)
        self.setGraphicsEffect(glow)

    def set_value(self, v):
        self.findChild(QLabel, "statValue").setText(str(v))


# ─── Vuln Card Widget ─────────────────────────────────────────────
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

        # CVE ID
        cve = QLabel(data.get("cve_id", "N/A"))
        cve.setStyleSheet(f"color:{C['blue']}; font-size:13px; font-weight:bold; font-family:Consolas;")
        cve.setFixedWidth(140)
        layout.addWidget(cve)

        # Tags
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

        # CVSS
        cvss = data.get("cvss")
        cvss_lbl = QLabel(f"CVSS {cvss:.1f}" if cvss else "CVSS -")
        cvss_lbl.setStyleSheet(f"color:{C['text2']}; font-size:12px; font-family:Consolas;")
        cvss_lbl.setFixedWidth(80)
        layout.addWidget(cvss_lbl)

        # Score
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

        # Title
        title = QLabel(data.get("title", ""))
        title.setStyleSheet(f"color:{C['text2']}; font-size:12px; font-family:'Microsoft YaHei';")
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


# ─── Main Panel ───────────────────────────────────────────────────
class AgentPanel(QWidget):

    def __init__(self, config, db_session_factory, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db_session_factory
        self.setObjectName("agentPanel")
        self._worker = None
        self._history = []
        self._current_vuln = None
        self._stream_buf = ""
        self._streaming = False

        self._animator = StreamAnimator()
        self._animator.chunk_ready.connect(self._on_stream_chunk)
        self._animator.finished.connect(self._on_stream_done)

        self._build_ui()
        self._apply_style()
        self._load_dashboard()

    def set_current_vuln(self, v):
        self._current_vuln = v

    # ── Build UI ────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Title Bar ───────────────────────────────────────────
        title_bar = QFrame()
        title_bar.setFixedHeight(48)
        title_bar.setObjectName("titleBar")
        tb = QHBoxLayout(title_bar)
        tb.setContentsMargins(16, 0, 16, 0)

        dot = QLabel("●")
        dot.setStyleSheet(f"color:{C['green']}; font-size:10px;")
        tb.addWidget(dot)

        r_icon = QLabel("R")
        r_icon.setFixedSize(28, 28)
        r_icon.setAlignment(Qt.AlignCenter)
        r_icon.setStyleSheet(
            f"color:{C['white']}; background:{C['green']}; "
            f"border-radius:14px; font-size:12px; font-weight:bold; font-family:Consolas;"
        )
        tb.addWidget(r_icon)
        tb.addSpacing(8)

        name = QLabel("Rcon")
        name.setStyleSheet(f"color:{C['text']}; font-size:15px; font-weight:600; font-family:'Microsoft YaHei';")
        tb.addWidget(name)
        tb.addStretch()

        self.btn_new = QPushButton("+ 新对话")
        self.btn_new.setObjectName("newBtn")
        self.btn_new.setCursor(Qt.PointingHandCursor)
        self.btn_new.clicked.connect(self._clear)
        tb.addWidget(self.btn_new)

        for txt, clr in [("—", C["text3"]), ("□", C["text3"]), ("×", C["red"])]:
            lbl = QLabel(txt)
            lbl.setStyleSheet(f"color:{clr}; font-size:14px; padding:0 6px;")
            tb.addWidget(lbl)

        root.addWidget(title_bar)

        # ── Content Area ────────────────────────────────────────
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
        self.chat_container.setObjectName("chatContainer")
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setContentsMargins(0, 16, 0, 16)
        self.chat_layout.setSpacing(0)
        self.chat_layout.addStretch()
        self.chat_scroll.setWidget(self.chat_container)
        self.chat_scroll.hide()
        self.content_layout.addWidget(self.chat_scroll)

        root.addWidget(self.content_stack, 1)

        # ── Quick Actions ───────────────────────────────────────
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

        # ── Input ───────────────────────────────────────────────
        inp = QFrame()
        inp.setObjectName("inputFrame")
        il = QHBoxLayout(inp)
        il.setContentsMargins(20, 12, 20, 20)
        il.setSpacing(14)

        self.input = QLineEdit()
        self.input.setObjectName("chatInput")
        self.input.setPlaceholderText("发送消息...")
        self.input.returnPressed.connect(self._send)
        il.addWidget(self.input, 1)

        self.btn_send = QPushButton("发送")
        self.btn_send.setObjectName("sendBtn")
        self.btn_send.setCursor(Qt.PointingHandCursor)
        self.btn_send.setFixedSize(88, 48)
        self.btn_send.clicked.connect(self._send)
        il.addWidget(self.btn_send)

        root.addWidget(inp)

    def _build_dashboard(self):
        """Build the dashboard with stat cards and vuln list."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        page = QWidget()
        page.setStyleSheet(f"background:{C['bg']};")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(32, 28, 32, 20)
        layout.setSpacing(24)

        # ── Header ──────────────────────────────────────────────
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
        t.setStyleSheet(f"color:{C['text']}; font-size:20px; font-weight:700; font-family:'Microsoft YaHei';")
        info.addWidget(t)
        s = QLabel("漏洞情报侦察兵")
        s.setStyleSheet(f"color:{C['text2']}; font-size:13px;")
        info.addWidget(s)
        header.addLayout(info)
        header.addStretch()
        layout.addLayout(header)

        # ── Stat Cards ──────────────────────────────────────────
        stats_label = QLabel("数据概览")
        stats_label.setStyleSheet(f"color:{C['text2']}; font-size:13px; font-weight:600; "
                                  f"font-family:'Microsoft YaHei'; margin-top:4px;")
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

        # ── Vuln List ───────────────────────────────────────────
        vuln_header = QHBoxLayout()
        vh_label = QLabel("最近漏洞")
        vh_label.setStyleSheet(f"color:{C['text2']}; font-size:13px; font-weight:600; "
                               f"font-family:'Microsoft YaHei';")
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

    def _load_dashboard(self):
        """Load stats and recent vulns into dashboard cards."""
        try:
            stats = query_database(self.db, "stats")
            if isinstance(stats, dict):
                self.card_total.set_value(stats["total"])
                self.card_kev.set_value(stats["kev"])
                self.card_unread.set_value(stats["unread"])
                self.card_high.set_value(stats["high"])

            vulns = query_database(self.db, "recent")
            if isinstance(vulns, list):
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
            self._append_html(self._html_user(cve_id))
            result = query_database(self.db, "cve", {"cve_id": cve_id})
            self._start_stream(result if isinstance(result, str) else str(result))

    # ── Style ───────────────────────────────────────────────────
    def _apply_style(self):
        self.setStyleSheet(f"""
            QWidget#agentPanel {{ background: {C['bg']}; }}
            QFrame#titleBar {{
                background: {C['bg2']};
                border-bottom: 1px solid {C['border']};
            }}
            QPushButton#newBtn {{
                background: {C['surface']};
                color: {C['blue']};
                border: 1px solid {C['border2']};
                border-radius: 14px;
                padding: 5px 16px;
                font-size: 12px;
                font-family: 'Microsoft YaHei';
            }}
            QPushButton#newBtn:hover {{
                background: {C['surface2']};
                border-color: {C['blue']};
            }}
            QPushButton#linkBtn {{
                background: transparent;
                color: {C['blue']};
                border: none;
                font-size: 12px;
                font-family: 'Microsoft YaHei';
            }}
            QPushButton#linkBtn:hover {{ color: {C['white']}; }}
            QFrame#chipFrame {{
                background: {C['bg']};
                border-top: 1px solid {C['border']};
            }}
            QPushButton#chipBtn {{
                background: {C['surface']};
                color: {C['text2']};
                border: 1px solid {C['border']};
                border-radius: 16px;
                padding: 7px 16px;
                font-size: 12px;
                font-family: 'Microsoft YaHei';
            }}
            QPushButton#chipBtn:hover {{
                background: {C['surface2']};
                color: {C['text']};
                border-color: {C['blue_dim']};
            }}
            QFrame#inputFrame {{
                background: {C['bg']};
                border-top: 1px solid {C['border']};
            }}
            QLineEdit#chatInput {{
                background: {C['surface']};
                color: {C['text']};
                border: 2px solid {C['border']};
                border-radius: 22px;
                padding: 12px 20px;
                font-size: 14px;
                font-family: 'Microsoft YaHei';
            }}
            QLineEdit#chatInput:focus {{ border-color: {C['blue']}; }}
            QLineEdit#chatInput::placeholder {{ color: {C['text3']}; }}
            QPushButton#sendBtn {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C['blue2']}, stop:1 {C['blue']});
                color: {C['white']};
                border: none;
                border-radius: 22px;
                font-size: 14px;
                font-weight: 600;
                font-family: 'Microsoft YaHei';
            }}
            QPushButton#sendBtn:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C['blue']}, stop:1 #4d9fff);
            }}
            QPushButton#sendBtn:disabled {{
                background: {C['surface2']};
                color: {C['text3']};
            }}
            QScrollArea {{ background: {C['bg']}; border: none; }}
            QScrollBar:vertical {{
                background: {C['bg']}; width: 5px; border: none;
            }}
            QScrollBar::handle:vertical {{
                background: {C['border2']}; border-radius: 2px; min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {C['text3']}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

    # ── Chat HTML ───────────────────────────────────────────────
    def _html_user(self, text):
        safe = self._esc(text)
        return f'''
        <div style="display:flex; justify-content:flex-end; margin:10px 48px 10px 80px;">
          <div style="background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C['blue2']},stop:1 {C['blue']});
               color:#fff; padding:12px 18px; border-radius:18px 18px 4px 18px;
               max-width:65%; font-size:14px; line-height:1.7; word-wrap:break-word;">
            {safe}
          </div>
        </div>'''

    def _html_ai(self, text, cursor=False):
        safe = self._esc(text)
        c = ' <span style="color:#3b82f6;">▌</span>' if cursor else ''
        return f'''
        <div style="display:flex; justify-content:flex-start; margin:10px 80px 10px 48px;">
          <div style="width:30px; height:30px; background:qlineargradient(x1:0,y1:0,x2:1,y2:1,
               stop:0 {C['blue2']},stop:1 {C['blue']}); border-radius:15px; flex-shrink:0;
               display:flex; align-items:center; justify-content:center; margin-right:10px; margin-top:4px;">
            <span style="color:white; font-size:12px; font-weight:bold; font-family:Consolas;">R</span>
          </div>
          <div style="background:{C['surface']}; color:{C['text']}; padding:12px 18px;
               border-radius:18px 18px 18px 4px; max-width:70%; font-size:14px;
               line-height:1.75; word-wrap:break-word; border:1px solid {C['border']};">
            {safe}{c}
          </div>
        </div>'''

    def _html_think(self, dots):
        return f'''
        <div style="display:flex; justify-content:flex-start; margin:10px 80px 10px 48px;">
          <div style="width:30px; height:30px; background:{C['surface2']}; border-radius:15px;
               flex-shrink:0; display:flex; align-items:center; justify-content:center;
               margin-right:10px; margin-top:4px;">
            <span style="color:{C['text3']}; font-size:12px; font-weight:bold; font-family:Consolas;">R</span>
          </div>
          <div style="background:{C['surface']}; color:{C['text3']}; padding:12px 18px;
               border-radius:18px 18px 18px 4px; font-size:14px; line-height:1.75;
               border:1px solid {C['border']}; display:flex; align-items:center; gap:6px;">
            <span style="color:{C['blue']};">●</span> 正在思考 <span>{dots}</span>
          </div>
        </div>'''

    def _esc(self, t):
        return (t.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace("\n", "<br>")
                 .replace("  ", "&nbsp;&nbsp;"))

    # ── Chat Management ─────────────────────────────────────────
    def _show_chat(self):
        self.dashboard.hide()
        self.chat_scroll.show()

    def _append_html(self, html):
        count = self.chat_layout.count()
        idx = max(0, count - 1)
        lbl = QLabel()
        lbl.setTextFormat(Qt.RichText)
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)
        lbl.setWordWrap(True)
        lbl.setText(html)
        lbl.setStyleSheet("background:transparent;")
        self.chat_layout.insertWidget(idx, lbl)
        QTimer.singleShot(50, lambda: self.chat_scroll.verticalScrollBar().setValue(
            self.chat_scroll.verticalScrollBar().maximum()))

    def _remove_last_widget(self):
        count = self.chat_layout.count()
        if count > 1:
            item = self.chat_layout.takeAt(count - 2)
            if item.widget():
                item.widget().deleteLater()

    # ── Think Animation ─────────────────────────────────────────
    def _start_think(self):
        self._think_phase = 0
        self._think_timer = QTimer()
        self._think_timer.timeout.connect(self._tick_think)
        self._think_timer.start(200)
        self._append_html(self._html_think("..."))

    def _tick_think(self):
        self._think_phase += 1
        dots = "." * (self._think_phase % 4)
        self._remove_last_widget()
        self._append_html(self._html_think(dots))

    def _stop_think(self):
        if hasattr(self, '_think_timer'):
            self._think_timer.stop()

    # ── Streaming ───────────────────────────────────────────────
    def _start_stream(self, text):
        self._stop_think()
        self._streaming = True
        self._stream_buf = ""
        self._append_html(self._html_ai("", cursor=True))
        self._animator.start(text, speed_ms=8)

    def _on_stream_chunk(self, chunk):
        self._stream_buf += chunk
        self._remove_last_widget()
        self._append_html(self._html_ai(self._stream_buf, cursor=True))

    def _on_stream_done(self):
        self._streaming = False
        self._remove_last_widget()
        self._append_html(self._html_ai(self._stream_buf, cursor=False))

    # ── Actions ─────────────────────────────────────────────────
    def _on_chip(self, label):
        qtype = {"数据库概览": "stats", "最近漏洞": "recent", "高危 Top10": "top_risk"}.get(label)
        if not qtype:
            return
        self._show_chat()
        self._append_html(self._html_user(f"[{label}]"))
        result = query_database(self.db, qtype)
        if isinstance(result, (dict, list)):
            import json
            self._start_stream(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            self._start_stream(str(result))

    def _send(self):
        msg = self.input.text().strip()
        if not msg or self._streaming:
            return
        self._show_chat()
        self._append_html(self._html_user(msg))
        self.input.clear()
        self._history.append({"role": "user", "content": msg})

        db_result = self._try_db(msg)
        if db_result is not None:
            if isinstance(db_result, (dict, list)):
                import json
                self._start_stream(json.dumps(db_result, ensure_ascii=False, indent=2))
            else:
                self._start_stream(str(db_result))
            return
        self._call_ai(msg)

    def _try_db(self, message):
        m = re.search(r'(CVE[-\s]?)?(\d{4})[-\s]?(\d{4,})', message.upper(), re.I)
        if m:
            return query_database(self.db, "cve", {"cve_id": f"CVE-{m.group(2)}-{m.group(3)}"})
        u = message.upper()
        if any(k in u for k in ["统计", "概览", "总数", "数据库"]):
            return query_database(self.db, "stats")
        if any(k in u for k in ["最近", "最新"]):
            return query_database(self.db, "recent")
        if any(k in u for k in ["高危", "严重", "TOP"]):
            return query_database(self.db, "top_risk")
        sm = re.search(r'(搜索|查找|查询)\s+(.+)', message, re.I)
        if sm:
            return query_database(self.db, "search", {"keyword": sm.group(2).strip()})
        return None

    def _call_ai(self, msg):
        cfg = getattr(self.config, 'agent', None)
        if not cfg or not getattr(cfg, 'api_key', ''):
            self._start_stream("[!] 未配置 API Key，请在设置 → Agent 配置中设置")
            return
        db_ctx = query_database(self.db, "stats")
        prompt = getattr(cfg, 'prompt', '你是网络安全专家')
        if isinstance(db_ctx, dict):
            prompt += f"\n\n数据库: 总{db_ctx['total']} KEV:{db_ctx['kev']} 未读:{db_ctx['unread']} 高危:{db_ctx['high']}"

        self.btn_send.setEnabled(False)
        self.btn_send.setText("...")
        self._start_think()

        self._worker = AgentWorker(
            getattr(cfg, 'protocol', '兼容 OpenAI'), cfg.api_key,
            getattr(cfg, 'base_url', 'https://api.openai.com/v1'),
            getattr(cfg, 'model', 'gpt-4o'), prompt,
            self._history[-10:], getattr(cfg, 'max_tokens', 2000)
        )
        self._worker.response_ready.connect(self._on_ok)
        self._worker.error_occurred.connect(self._on_err)
        self._worker.start()

    def _on_ok(self, resp):
        self._start_stream(resp)
        self._history.append({"role": "assistant", "content": resp})
        self.btn_send.setEnabled(True)
        self.btn_send.setText("发送")

    def _on_err(self, err):
        self._stop_think()
        self._start_stream(f"[!] {err}")
        self.btn_send.setEnabled(True)
        self.btn_send.setText("发送")

    def _clear(self):
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._history.clear()
        self._streaming = False
        self._stop_think()
        self.chat_scroll.hide()
        self.dashboard.show()
        self._load_dashboard()
