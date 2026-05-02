"""AI Push briefing window."""

import httpx
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextBrowser,
    QPushButton, QApplication,
)
from loguru import logger


class AIPushWorker(QThread):
    response_ready = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, agent_config, prompt: str, parent=None):
        super().__init__(parent)
        self.agent_config = agent_config
        self.prompt = prompt

    def run(self):
        try:
            result = self._call_llm()
            self.response_ready.emit(result)
        except Exception as e:
            logger.exception("AI push generation failed")
            self.error_occurred.emit(f"{type(e).__name__}: {e}")

    def _call_llm(self) -> str:
        base_url = self.agent_config.base_url.rstrip("/")
        url = f"{base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.agent_config.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.agent_config.model,
            "messages": [
                {"role": "system", "content": "你是专业漏洞情报分析员，只基于用户提供的数据生成推送，不编造信息。"},
                {"role": "user", "content": self.prompt},
            ],
            "temperature": 0.2,
            "max_tokens": getattr(self.agent_config, "max_tokens", 3000),
        }
        resp = httpx.post(url, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


STYLE = """
QDialog {
    background: #0d1117; font-family: 'Microsoft YaHei';
}
QLabel#statusLabel {
    color: #58a6ff; font-size: 13px; font-family: 'Microsoft YaHei';
}
QTextBrowser {
    background: #0d1117; color: #c9d1d9;
    border: 1px solid #1c2940; border-radius: 8px;
    font-size: 13px; font-family: 'Microsoft YaHei', Consolas;
    padding: 12px;
}
QPushButton {
    background: #21262d; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 6px;
    padding: 6px 16px; font-size: 12px;
}
QPushButton:hover { background: #30363d; border-color: #58a6ff; }
"""


class AIPushWindow(QDialog):
    @classmethod
    def waiting(cls, parent=None):
        win = cls.__new__(cls)
        QDialog.__init__(win, parent)
        win.setStyleSheet(STYLE)
        win.setWindowTitle("AI推送 — 生成中")
        win.resize(640, 320)
        layout = QVBoxLayout(win)
        status = QLabel("AI推送正在生成并优化，请稍作等待...")
        status.setObjectName("statusLabel")
        layout.addWidget(status)
        browser = QTextBrowser()
        browser.setMarkdown("## 请稍作等待\n\nAI 推送文本正在后台生成并优化，完成后会自动保存到个人库。")
        layout.addWidget(browser)
        btn = QPushButton("关闭")
        btn.clicked.connect(win.close)
        layout.addWidget(btn, alignment=Qt.AlignRight)
        return win

    @classmethod
    def from_report(cls, session_factory, report_id: int, parent=None):
        from app.db.models import AIPushReport
        win = cls.__new__(cls)
        QDialog.__init__(win, parent)
        win.setStyleSheet(STYLE)
        win.setWindowTitle("AI推送 — 高危漏洞简报")
        win.resize(780, 660)

        session = session_factory()
        try:
            rpt = session.get(AIPushReport, report_id)
            title = rpt.title if rpt else "报告"
            content = (rpt.final_content or rpt.rule_content) if rpt else "报告数据不可用"
            gen_time = str(rpt.optimized_at or rpt.generated_at or "")[:19] if rpt else ""
        finally:
            session.close()

        layout = QVBoxLayout(win)
        layout.setSpacing(8)
        status = QLabel(f"生成时间：{gen_time}")
        status.setObjectName("statusLabel")
        layout.addWidget(status)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setMarkdown(content)
        layout.addWidget(browser)
        btns = QHBoxLayout()
        btn_copy = QPushButton("复制")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(browser.toMarkdown()))
        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(win.close)
        btns.addWidget(btn_copy)
        btns.addStretch()
        btns.addWidget(btn_close)
        layout.addLayout(btns)
        return win

    @classmethod
    def message(cls, title: str, body: str, parent=None):
        win = cls.__new__(cls)
        QDialog.__init__(win, parent)
        win.setStyleSheet(STYLE)
        win.setWindowTitle(title)
        win.resize(500, 280)
        layout = QVBoxLayout(win)
        browser = QTextBrowser()
        browser.setMarkdown(f"# {title}\n\n{body}")
        layout.addWidget(browser)
        btn = QPushButton("关闭")
        btn.clicked.connect(win.close)
        layout.addWidget(btn, alignment=Qt.AlignRight)
        return win
