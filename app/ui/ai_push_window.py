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


class AIPushWindow(QDialog):
    def __init__(self, session_factory, config, parent=None):
        super().__init__(parent)
        self.session_factory = session_factory
        self.config = config
        self._worker = None

        self.setWindowTitle("AI推送 — 高危漏洞简报")
        self.resize(780, 660)

        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        self.status = QLabel("正在生成推送...")
        self.status.setStyleSheet("color:#58a6ff; font-size:13px; font-family:'Microsoft YaHei';")
        layout.addWidget(self.status)

        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)
        self.browser.setStyleSheet("""
            QTextBrowser {
                background: #0d1117; color: #c9d1d9;
                border: 1px solid #1c2940; border-radius: 8px;
                font-size: 13px; font-family: 'Microsoft YaHei', Consolas;
                padding: 12px;
            }
        """)
        layout.addWidget(self.browser)

        btns = QHBoxLayout()
        self.btn_copy = QPushButton("复制")
        self.btn_refresh = QPushButton("重新生成")
        self.btn_close = QPushButton("关闭")
        for b in [self.btn_copy, self.btn_refresh, self.btn_close]:
            b.setStyleSheet("""
                QPushButton {
                    background: #21262d; color: #c9d1d9;
                    border: 1px solid #30363d; border-radius: 6px;
                    padding: 6px 16px; font-size: 12px;
                }
                QPushButton:hover { background: #30363d; border-color: #58a6ff; }
            """)
        btns.addWidget(self.btn_copy)
        btns.addWidget(self.btn_refresh)
        btns.addStretch()
        btns.addWidget(self.btn_close)
        layout.addLayout(btns)

        self.btn_copy.clicked.connect(self._copy)
        self.btn_refresh.clicked.connect(self.load_push)
        self.btn_close.clicked.connect(self.close)

        self.load_push()

    def load_push(self):
        if self._worker and self._worker.isRunning():
            self.status.setText("AI 正在生成中，请稍候...")
            return

        try:
            from app.services.ai_push_service import (
                get_ai_push_candidates,
                build_vuln_push_payload,
                build_rule_based_push,
                build_ai_push_prompt,
            )

            session = self.session_factory()
            try:
                candidates = get_ai_push_candidates(session, limit=5, days=14)
                items = [build_vuln_push_payload(session, v) for v in candidates]
            finally:
                session.close()

            rule_md = build_rule_based_push(items)
            self.browser.setMarkdown(rule_md)

            if items:
                self.status.setText(f"已生成推送：{len(items)} 个漏洞")
            else:
                self.status.setText("暂无符合条件的高危漏洞")
                return

            agent_cfg = getattr(self.config, "agent", None)
            if agent_cfg and getattr(agent_cfg, "api_key", ""):
                prompt = build_ai_push_prompt(items)
                self.status.setText("正在调用 AI 优化推送...")
                self._start_ai_worker(prompt, agent_cfg)

        except Exception as e:
            logger.exception("AI push load failed")
            self.status.setText(f"加载失败: {type(e).__name__}")

    def _start_ai_worker(self, prompt, agent_cfg):
        if self._worker and self._worker.isRunning():
            self.status.setText("AI 正在生成中，请稍候...")
            return

        self.btn_refresh.setEnabled(False)
        self._worker = AIPushWorker(agent_cfg, prompt, self)
        self._worker.response_ready.connect(self._on_ai_ok)
        self._worker.error_occurred.connect(self._on_ai_err)
        self._worker.finished.connect(lambda: self.btn_refresh.setEnabled(True))
        self._worker.start()

    def _on_ai_ok(self, text):
        self.browser.setMarkdown(text)
        self.status.setText("AI推送已生成")

    def _on_ai_err(self, err):
        self.status.setText(f"AI生成失败，已保留规则推送")

    def _copy(self):
        QApplication.clipboard().setText(self.browser.toMarkdown())
        self.status.setText("已复制到剪贴板")
