import re
import json
from PySide6.QtCore import Qt, Signal, QThread, QTimer
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QFrame, QLineEdit, QApplication, QSizePolicy,
    QGraphicsDropShadowEffect, QTextBrowser
)
from loguru import logger


# ─── Web Search ───────────────────────────────────────────────────
def search_web(query, max_results=5):
    """Search the web for vulnerability intelligence."""
    results = []
    try:
        import httpx
        # Search NVD
        if "CVE" in query.upper() or re.search(r'\d{4}-\d{4,}', query):
            cve_match = re.search(r'(CVE-)?(\d{4}-\d{4,})', query, re.I)
            if cve_match:
                cve_id = f"CVE-{cve_match.group(2)}"
                try:
                    resp = httpx.get(
                        f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": cve_id},
                        timeout=10.0
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        vulns = data.get("vulnerabilities", [])
                        if vulns:
                            cve = vulns[0].get("cve", {})
                            desc = cve.get("descriptions", [{}])
                            desc_text = desc[0].get("value", "") if desc else ""
                            results.append({
                                "source": "NVD",
                                "title": f"{cve_id} - {desc_text[:100]}",
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                "snippet": desc_text[:300]
                            })
                except:
                    pass

        # Search CISA KEV
        try:
            resp = httpx.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=10.0
            )
            if resp.status_code == 200:
                kev_data = resp.json()
                for vuln in kev_data.get("vulnerabilities", [])[:100]:
                    cve_id = vuln.get("cveID", "")
                    name = vuln.get("vulnerabilityName", "")
                    desc = vuln.get("shortDescription", "")
                    if (query.upper() in cve_id.upper() or
                        query.upper() in name.upper() or
                        query.upper() in desc.upper()):
                        results.append({
                            "source": "CISA KEV",
                            "title": f"{cve_id} - {name}",
                            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "snippet": desc[:300]
                        })
                        break
        except:
            pass

        # Search GitHub Advisory
        try:
            headers = {"Accept": "application/vnd.github+json"}
            resp = httpx.get(
                "https://api.github.com/advisories",
                params={"per_page": 5, "type": "reviewed", "sort": "published", "direction": "desc"},
                headers=headers,
                timeout=10.0
            )
            if resp.status_code == 200:
                for adv in resp.json():
                    ghsa = adv.get("ghsa_id", "")
                    summary = adv.get("summary", "")
                    if query.upper() in summary.upper() or query.upper() in ghsa.upper():
                        results.append({
                            "source": "GitHub Advisory",
                            "title": f"{ghsa} - {summary[:80]}",
                            "url": adv.get("html_url", ""),
                            "snippet": adv.get("description", "")[:300]
                        })
        except:
            pass
    except Exception as e:
        logger.error(f"Web search error: {e}")

    return results[:max_results]


# ─── Worker with Pause Support ────────────────────────────────────
class AnalysisWorker(QThread):
    chunk_received = Signal(str)
    thinking_update = Signal(str)
    finished_signal = Signal()
    error_signal = Signal(str)

    def __init__(self, protocol, api_key, base_url, model, prompt, messages, max_tokens=4000):
        super().__init__()
        self.protocol = protocol
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.system_prompt = prompt
        self.messages = messages
        self.max_tokens = max_tokens
        self._paused = False
        self._cancelled = False

    def run(self):
        try:
            import httpx
            self.thinking_update.emit("正在分析...")

            if "Anthropic" in self.protocol:
                result = self._call_anthropic()
            else:
                result = self._call_openai()

            if not self._cancelled:
                self.chunk_received.emit(result)
                self.finished_signal.emit()
        except Exception as e:
            if not self._cancelled:
                logger.error(f"AI analysis error: {e}")
                self.error_signal.emit(str(e))

    def _call_openai(self):
        import httpx
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        all_msgs = [{"role": "system", "content": self.system_prompt}] + self.messages
        data = {"model": self.model, "messages": all_msgs, "max_tokens": self.max_tokens, "temperature": 0.7}
        resp = httpx.post(f"{self.base_url}/chat/completions", headers=headers, json=data, timeout=120.0)
        if resp.status_code != 200:
            try:
                detail = resp.json().get("error", {}).get("message", resp.text[:300])
            except:
                detail = resp.text[:300]
            raise Exception(f"API {resp.status_code}: {detail}")
        result = resp.json()
        if "choices" not in result:
            raise Exception(f"响应格式异常: {str(result)[:200]}")
        return result["choices"][0]["message"]["content"]

    def _call_anthropic(self):
        import httpx
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        data = {"model": self.model, "max_tokens": self.max_tokens, "system": self.system_prompt, "messages": self.messages}
        resp = httpx.post(f"{self.base_url}/messages", headers=headers, json=data, timeout=120.0)
        if resp.status_code != 200:
            try:
                detail = resp.json().get("error", {}).get("message", resp.text[:300])
            except:
                detail = resp.text[:300]
            raise Exception(f"API {resp.status_code}: {detail}")
        return resp.json()["content"][0]["text"]

    def cancel(self):
        self._cancelled = True


# ─── Markdown to HTML ─────────────────────────────────────────────
def md_to_html(text):
    """Convert markdown to styled HTML for dark theme with full table support."""
    if not text:
        return ""

    # ── Step 1: Extract and protect code blocks BEFORE escaping ──
    code_blocks = []

    def extract_code_block(m):
        lang = m.group(1) or ""
        code = m.group(2)
        idx = len(code_blocks)
        code_blocks.append((lang, code))
        return f"__CODE_BLOCK_{idx}__"

    # Match ```language\n...``` (with or without language, with or without newline)
    text = re.sub(r'```(\w*)\n?(.*?)```', extract_code_block, text, flags=re.DOTALL)

    # ── Step 2: Escape HTML entities ──
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── Step 3: Process code blocks (replace placeholders) ──
    def restore_code_block(m):
        idx = int(m.group(1))
        lang, code = code_blocks[idx]
        # Escape HTML in code
        code = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        lang_label = ""
        if lang:
            lang_label = (f'<div style="background:#1c2940; color:#8b949e; padding:4px 12px; '
                          f'font-size:11px; font-family:Consolas; border-radius:8px 8px 0 0; '
                          f'border:1px solid #1c2940; border-bottom:none;">{lang}</div>')
            return (f'{lang_label}<pre style="background:#0d1117; border:1px solid #1c2940; '
                    f'border-radius:0 0 8px 8px; padding:12px 14px; margin:0 0 6px 0; '
                    f'font-family:Consolas,Courier; font-size:13px; color:#e6edf3; '
                    f'overflow-x:auto; white-space:pre-wrap; line-height:1.5;">'
                    f'{code.strip()}</pre>')
        else:
            return (f'<pre style="background:#0d1117; border:1px solid #1c2940; border-radius:8px; '
                    f'padding:12px 14px; margin:6px 0; font-family:Consolas,Courier; font-size:13px; '
                    f'color:#e6edf3; overflow-x:auto; white-space:pre-wrap; line-height:1.5;">'
                    f'{code.strip()}</pre>')

    text = re.sub(r'__CODE_BLOCK_(\d+)__', restore_code_block, text)

    # Tables
    def replace_table(m):
        table_text = m.group(0).strip()
        rows = [r.strip() for r in table_text.split('\n') if r.strip()]
        if len(rows) < 2:
            return table_text
        header_cells = [c.strip() for c in rows[0].split('|') if c.strip()]
        data_start = 1
        if len(rows) > 1 and re.match(r'^[\s|:\-]+$', rows[1]):
            data_start = 2
        data_rows = []
        for row in rows[data_start:]:
            cells = [c.strip() for c in row.split('|') if c.strip()]
            if cells:
                data_rows.append(cells)

        html = '<table style="width:100%; border-collapse:collapse; margin:8px 0; font-size:13px; line-height:1.5;">'
        html += '<thead><tr>'
        for h in header_cells:
            html += (f'<th style="background:#111820; color:#58a6ff; font-weight:600; '
                     f'text-align:left; padding:8px 12px; border:1px solid #1c2940; '
                     f'font-size:12px; white-space:nowrap;">{h}</th>')
        html += '</tr></thead><tbody>'
        for i, row in enumerate(data_rows):
            bg = '#0f1520' if i % 2 == 0 else '#131a28'
            html += '<tr>'
            for j, cell in enumerate(row):
                cell_html = re.sub(r'\*\*(.+?)\*\*', r'<b style="color:#e6edf3;">\1</b>', cell)
                html += (f'<td style="background:{bg}; color:#c9d1d9; padding:7px 12px; '
                         f'border:1px solid #1c2940; vertical-align:top;">{cell_html}</td>')
            for _ in range(len(header_cells) - len(row)):
                html += f'<td style="background:{bg}; padding:7px 12px; border:1px solid #1c2940;"></td>'
            html += '</tr>'
        html += '</tbody></table>'
        return html

    # Match GFM tables: header row + separator + data rows
    table_pattern = re.compile(
        r'((?:^\|.+\|\s*\n)+(?:^\|[-:\s|]+\|\s*\n)+(?:^\|.+\|\s*\n?)+)',
        re.MULTILINE
    )
    text = table_pattern.sub(replace_table, text)

    # Inline code
    text = re.sub(r'`([^`]+)`', r'<code style="background:#161b22; color:#79c0ff; padding:2px 6px; '
                  r'border-radius:4px; border:1px solid #1c2940; font-family:Consolas; font-size:12px;">\1</code>', text)

    # Headers
    text = re.sub(r'^### (.+)$', r'<h3 style="color:#58a6ff; font-size:15px; font-weight:600; margin:12px 0 4px; padding-bottom:3px; border-bottom:1px solid #1c2940;">\1</h3>', text, flags=re.M)
    text = re.sub(r'^## (.+)$', r'<h2 style="color:#58a6ff; font-size:17px; font-weight:700; margin:14px 0 6px; padding-bottom:4px; border-bottom:1px solid #253550;">\1</h2>', text, flags=re.M)
    text = re.sub(r'^# (.+)$', r'<h1 style="color:#58a6ff; font-size:19px; font-weight:800; margin:16px 0 8px; padding-bottom:5px; border-bottom:2px solid #253550;">\1</h1>', text, flags=re.M)

    # Bold & Italic
    text = re.sub(r'\*\*(.+?)\*\*', r'<b style="color:#f0f6fc;">\1</b>', text)
    text = re.sub(r'\*(.+?)\*', r'<i style="color:#8b949e;">\1</i>', text)

    # Lists
    def replace_ul(m):
        content = m.group(1)
        return (f'<div style="margin:2px 0; padding-left:16px; color:#c9d1d9; '
                f'line-height:1.6;"><span style="color:#3b82f6; margin-right:6px;">•</span>{content}</div>')
    text = re.sub(r'^[\-\*] (.+)$', replace_ul, text, flags=re.M)

    def replace_ol(m):
        num = m.group(1)
        content = m.group(2)
        return (f'<div style="margin:2px 0; padding-left:20px; color:#c9d1d9; '
                f'line-height:1.6;"><span style="color:#3b82f6; margin-right:6px; font-weight:600;">{num}.</span>{content}</div>')
    text = re.sub(r'^(\d+)\. (.+)$', replace_ol, text, flags=re.M)

    # HR
    text = re.sub(r'^---+$', r'<hr style="border:none; border-top:1px solid #1c2940; margin:10px 0;">', text, flags=re.M)

    # Links
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color:#58a6ff; text-decoration:none; border-bottom:1px solid #1c2940;">\1</a>', text)

    # Paragraphs
    text = re.sub(r'\n\n+', r'<div style="margin:6px 0;"></div>', text)
    text = re.sub(r'\n', r'<br>', text)

    return text


# ─── Style ────────────────────────────────────────────────────────
STYLE = """
QDialog {
    background: #0b0f19; color: #e2e8f0;
    font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QLabel#title { color: #e6edf3; font-size: 18px; font-weight: bold; }
QLabel#subtitle { color: #8b949e; font-size: 13px; }
QTextEdit#thinking {
    background: #131a28; color: #8b949e;
    border: 1px solid #1c2940; border-radius: 8px;
    font-size: 12px; padding: 10px;
    font-family: 'Microsoft YaHei', 'Consolas', monospace;
}
QTextBrowser#output {
    background: #0f1520; color: #e2e8f0;
    border: 1px solid #1c2940; border-radius: 8px;
    font-size: 14px; padding: 16px;
    font-family: 'Microsoft YaHei', 'Consolas', monospace;
    selection-background-color: #264f78;
}
QLineEdit#continueInput {
    background: #131a28; color: #e2e8f0;
    border: 1px solid #1c2940; border-radius: 18px;
    padding: 10px 16px; font-size: 13px;
    font-family: 'Microsoft YaHei', monospace;
}
QLineEdit#continueInput:focus { border-color: #3b82f6; }
QLineEdit#continueInput:disabled { background: #0b0f19; color: #3d4450; }
QPushButton {
    padding: 8px 18px; border: 1px solid #1c2940;
    border-radius: 8px; font-size: 13px;
    background: #131a28; color: #e2e8f0;
    font-family: 'Microsoft YaHei';
}
QPushButton:hover { background: #1a2435; border-color: #3b82f6; }
QPushButton#runBtn {
    background: #238636; color: white; border: 1px solid #2ea043; font-weight: bold;
}
QPushButton#runBtn:hover { background: #2ea043; }
QPushButton#pauseBtn {
    background: #d29922; color: white; border: 1px solid #e3b341; font-weight: bold;
}
QPushButton#pauseBtn:hover { background: #e3b341; }
QPushButton#copyBtn {
    background: #1f6feb; color: white; border: 1px solid #388bfd;
}
QPushButton#copyBtn:hover { background: #388bfd; }
QPushButton#continueBtn {
    background: #238636; color: white; border: 1px solid #2ea043;
}
QPushButton#continueBtn:hover { background: #2ea043; }
QPushButton#continueBtn:disabled { background: #161b22; color: #3d4450; border-color: #1c2940; }
"""


class AIAnalysisWindow(QDialog):
    """AI Analysis window with pause/resume and continuous chat."""

    def __init__(self, vuln: dict, config, parent=None):
        super().__init__(parent)
        self._vuln = vuln
        self._config = config
        self._worker = None
        self._history = []
        self._full_response = ""
        self._is_running = False
        self._is_paused = False

        cve_id = vuln.get("cve_id") or vuln.get("ghsa_id") or vuln.get("osv_id") or "N/A"
        self.setWindowTitle(f"Rcon AI 分析 — {cve_id}")
        self.setMinimumSize(850, 650)
        self.resize(950, 750)
        self.setStyleSheet(STYLE)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Header ──────────────────────────────────────────────
        header = QVBoxLayout()
        title = QLabel(f"🔍 {cve_id}")
        title.setObjectName("title")
        header.addWidget(title)

        vuln_title = vuln.get("title", "")[:80]
        subtitle = QLabel(vuln_title)
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        header.addWidget(subtitle)

        tags = QHBoxLayout()
        tags.setSpacing(6)
        score = vuln.get("action_value_score", 0) or 0
        if score >= 80:
            tags.addWidget(self._tag("极高风险", "#ef4444"))
        elif score >= 60:
            tags.addWidget(self._tag("高风险", "#f59e0b"))
        if vuln.get("is_kev"):
            tags.addWidget(self._tag("KEV", "#ef4444"))
        if vuln.get("has_poc_signal"):
            tags.addWidget(self._tag("PoC", "#f59e0b"))
        if vuln.get("has_patch"):
            tags.addWidget(self._tag("有补丁", "#22c55e"))
        tags.addStretch()
        header.addLayout(tags)
        layout.addLayout(header)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#1c2940;")
        layout.addWidget(sep)

        # ── Thinking panel ──────────────────────────────────────
        self.thinking_output = QTextEdit()
        self.thinking_output.setObjectName("thinking")
        self.thinking_output.setReadOnly(True)
        self.thinking_output.setMaximumHeight(100)
        self.thinking_output.setPlaceholderText("等待分析...")
        layout.addWidget(self.thinking_output)

        # ── Analysis output ─────────────────────────────────────
        self.analysis_output = QTextBrowser()
        self.analysis_output.setObjectName("output")
        self.analysis_output.setOpenExternalLinks(True)
        self.analysis_output.setPlaceholderText("分析结果将在这里显示...")
        layout.addWidget(self.analysis_output, 1)

        # ── Continue chat input ─────────────────────────────────
        continue_frame = QFrame()
        cf_layout = QHBoxLayout(continue_frame)
        cf_layout.setContentsMargins(0, 0, 0, 0)
        cf_layout.setSpacing(10)

        self.continue_input = QLineEdit()
        self.continue_input.setObjectName("continueInput")
        self.continue_input.setPlaceholderText("分析完成后可继续提问...")
        self.continue_input.returnPressed.connect(self._continue_chat)
        cf_layout.addWidget(self.continue_input, 1)

        self.btn_continue = QPushButton("继续分析")
        self.btn_continue.setObjectName("continueBtn")
        self.btn_continue.setFixedHeight(38)
        self.btn_continue.clicked.connect(self._continue_chat)
        self.btn_continue.setEnabled(False)
        cf_layout.addWidget(self.btn_continue)

        layout.addWidget(continue_frame)

        # ── Bottom buttons ──────────────────────────────────────
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.btn_run = QPushButton("🚀 开始分析")
        self.btn_run.setObjectName("runBtn")
        self.btn_run.clicked.connect(self._toggle_analysis)
        btn_layout.addWidget(self.btn_run)

        self.btn_copy = QPushButton("📋 复制")
        self.btn_copy.setObjectName("copyBtn")
        self.btn_copy.clicked.connect(self._copy_result)
        self.btn_copy.setEnabled(False)
        btn_layout.addWidget(self.btn_copy)

        btn_layout.addStretch()

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self._on_close)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

        # Auto-start
        QTimer.singleShot(300, self._start_analysis)

    def _tag(self, text, color):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color:{color}; font-size:11px; font-weight:bold; "
            f"background:{color}18; border:1px solid {color}40; "
            f"border-radius:4px; padding:2px 8px;"
        )
        lbl.setFixedHeight(20)
        return lbl

    def _build_prompt(self, extra_context=""):
        v = self._vuln
        vuln_id = v.get('cve_id') or v.get('ghsa_id') or v.get('osv_id') or 'N/A'
        prompt = f"""请分析以下漏洞：

漏洞ID: {vuln_id}
标题: {v.get('title', '')}
严重等级: {v.get('severity', 'UNKNOWN')}
CVSS评分: {v.get('cvss_score', '-')}
CVSS向量: {v.get('cvss_vector', '-')}
EPSS分数: {v.get('epss_score', '-')}
EPSS百分位: {v.get('epss_percentile', '-')}
CISA KEV: {'是' if v.get('is_kev') else '否'}
公开PoC: {'是' if v.get('has_poc_signal') else '否'}
官方补丁: {'是' if v.get('has_patch') else '否'}
数据来源: {v.get('source', '-')}
处置评分: {v.get('action_value_score', 0):.0f}/100

漏洞描述:
{v.get('description', '')[:2000]}

评分依据:
{v.get('action_value_reason', '')}"""

        if extra_context:
            prompt += f"\n\n补充信息:\n{extra_context}"

        prompt += """

请用 Markdown 格式从以下维度进行详细分析：
## 漏洞危害性评估
## 实际利用风险
## 影响范围分析
## 修复优先级建议
## 具体修复措施"""
        return prompt

    def _toggle_analysis(self):
        """Toggle between start/pause."""
        if self._is_running:
            self._pause_analysis()
        else:
            self._start_analysis()

    def _start_analysis(self):
        agent_cfg = getattr(self._config, 'agent', None)
        if not agent_cfg:
            self.thinking_output.setPlainText("⚠️ 未配置 Agent")
            return

        api_key = getattr(agent_cfg, 'api_key', '')
        if not api_key:
            self.thinking_output.setPlainText("⚠️ 未配置 API Key")
            return

        protocol = getattr(agent_cfg, 'protocol', '兼容 OpenAI')
        base_url = getattr(agent_cfg, 'base_url', 'https://api.openai.com/v1')
        model = getattr(agent_cfg, 'model', 'gpt-4o')
        max_tokens = getattr(agent_cfg, 'max_tokens', 4000)
        system_prompt = getattr(agent_cfg, 'prompt', '你是一个网络安全专家')

        # Auto web search
        cve_id = self._vuln.get("cve_id") or self._vuln.get("ghsa_id") or ""
        web_context = ""
        if cve_id:
            self.thinking_output.setPlainText("🌐 正在联网搜索相关情报...")
            QApplication.processEvents()
            try:
                results = search_web(cve_id)
                if results:
                    web_context = "联网搜索到的相关情报:\n"
                    for r in results:
                        web_context += f"- [{r['source']}] {r['title']}\n  {r['snippet']}\n  链接: {r['url']}\n\n"
                    self.thinking_output.append(f"> 找到 {len(results)} 条相关情报")
            except Exception as e:
                self.thinking_output.append(f"> 联网搜索异常: {e}")

        user_msg = self._build_prompt(web_context)
        self._history = [{"role": "user", "content": user_msg}]

        self._is_running = True
        self._is_paused = False
        self.btn_run.setText("⏸ 暂停")
        self.btn_run.setObjectName("pauseBtn")
        self.btn_run.setStyleSheet("""
            QPushButton {
                background: #d29922; color: white; border: 1px solid #e3b341;
                font-weight: bold; border-radius: 8px; font-size: 13px;
                padding: 8px 18px; font-family: 'Microsoft YaHei';
            }
            QPushButton:hover { background: #e3b341; }
        """)
        self.continue_input.setEnabled(False)
        self.continue_input.setPlaceholderText("分析中，请等待...")
        self.btn_continue.setEnabled(False)
        self.thinking_output.clear()
        self.analysis_output.clear()
        self._full_response = ""

        self._worker = AnalysisWorker(
            protocol, api_key, base_url, model,
            system_prompt, self._history, max_tokens
        )
        self._worker.thinking_update.connect(self._on_thinking)
        self._worker.chunk_received.connect(self._on_result)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.error_signal.connect(self._on_error)
        self._worker.start()

    def _pause_analysis(self):
        """Pause/cancel the current analysis."""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.terminate()
            self._worker.wait(2000)

        self._is_running = False
        self._is_paused = True
        self.btn_run.setText("🚀 继续分析")
        self.btn_run.setObjectName("runBtn")
        self.btn_run.setStyleSheet("""
            QPushButton {
                background: #238636; color: white; border: 1px solid #2ea043;
                font-weight: bold; border-radius: 8px; font-size: 13px;
                padding: 8px 18px; font-family: 'Microsoft YaHei';
            }
            QPushButton:hover { background: #2ea043; }
        """)
        self.continue_input.setEnabled(True)
        self.continue_input.setPlaceholderText("可补充信息后继续分析...")
        self.btn_continue.setEnabled(True)
        self.thinking_output.append("> ⏸ 已暂停，可补充信息后继续")

    def _continue_chat(self):
        msg = self.continue_input.text().strip()
        if not msg:
            return

        self.continue_input.clear()
        self._history.append({"role": "user", "content": msg})

        agent_cfg = getattr(self._config, 'agent', None)
        if not agent_cfg or not getattr(agent_cfg, 'api_key', ''):
            self.thinking_output.append("⚠️ 未配置 API Key")
            return

        api_key = agent_cfg.api_key
        protocol = getattr(agent_cfg, 'protocol', '兼容 OpenAI')
        base_url = getattr(agent_cfg, 'base_url', 'https://api.openai.com/v1')
        model = getattr(agent_cfg, 'model', 'gpt-4o')
        max_tokens = getattr(agent_cfg, 'max_tokens', 4000)
        system_prompt = getattr(agent_cfg, 'prompt', '你是网络安全专家')

        self._is_running = True
        self._is_paused = False
        self.btn_run.setText("⏸ 暂停")
        self.btn_run.setObjectName("pauseBtn")
        self.btn_run.setStyleSheet("""
            QPushButton {
                background: #d29922; color: white; border: 1px solid #e3b341;
                font-weight: bold; border-radius: 8px; font-size: 13px;
                padding: 8px 18px; font-family: 'Microsoft YaHei';
            }
            QPushButton:hover { background: #e3b341; }
        """)
        self.continue_input.setEnabled(False)
        self.continue_input.setPlaceholderText("分析中，请等待...")
        self.btn_continue.setEnabled(False)
        self.thinking_output.append(f"\n> 用户: {msg}")

        self._worker = AnalysisWorker(
            protocol, api_key, base_url, model,
            system_prompt, self._history[-10:], max_tokens
        )
        self._worker.thinking_update.connect(self._on_thinking)
        self._worker.chunk_received.connect(self._on_result)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.error_signal.connect(self._on_error)
        self._worker.start()

    def _on_thinking(self, msg):
        self.thinking_output.append(f"> {msg}")

    def _on_result(self, result):
        self._full_response = result
        self._history.append({"role": "assistant", "content": result})
        html = md_to_html(result)
        self.analysis_output.setHtml(f"""
        <div style="color:#c9d1d9; line-height:1.6; font-size:14px;
             font-family:'Microsoft YaHei','Consolas',monospace; padding:4px 0;">
            {html}
        </div>
        """)
        self.btn_copy.setEnabled(True)

    def _on_finished(self):
        self._is_running = False
        self._is_paused = False
        self.btn_run.setText("🚀 开始分析")
        self.btn_run.setObjectName("runBtn")
        self.btn_run.setStyleSheet("""
            QPushButton {
                background: #238636; color: white; border: 1px solid #2ea043;
                font-weight: bold; border-radius: 8px; font-size: 13px;
                padding: 8px 18px; font-family: 'Microsoft YaHei';
            }
            QPushButton:hover { background: #2ea043; }
        """)
        self.continue_input.setEnabled(True)
        self.continue_input.setPlaceholderText("可继续提问...")
        self.btn_continue.setEnabled(True)
        self.thinking_output.append("> ✅ 分析完成")

        # Save analysis
        if self._full_response:
            self._save_analysis()

    def _on_error(self, error):
        self._is_running = False
        self._is_paused = False
        self.btn_run.setText("🚀 开始分析")
        self.btn_run.setObjectName("runBtn")
        self.btn_run.setStyleSheet("""
            QPushButton {
                background: #238636; color: white; border: 1px solid #2ea043;
                font-weight: bold; border-radius: 8px; font-size: 13px;
                padding: 8px 18px; font-family: 'Microsoft YaHei';
            }
            QPushButton:hover { background: #2ea043; }
        """)
        self.continue_input.setEnabled(True)
        self.btn_continue.setEnabled(True)
        self.thinking_output.append(f"> ❌ 错误: {error}")
        self.analysis_output.setHtml(f"""
        <div style="color:#ef4444;">
            <p style="font-size:15px;">分析失败</p>
            <p style="color:#8b949e; font-size:13px; margin-top:8px;">{error}</p>
        </div>
        """)

    def _save_analysis(self):
        """Save AI analysis to database, file, and auto-watch."""
        try:
            from app.db.database import get_session
            from app.db import repositories as repo
            from app.utils.analysis_storage import save_analysis, list_analyses

            session = get_session()
            try:
                vuln_id = self._vuln.get("id")
                vuln_key = self._vuln.get("cve_id") or self._vuln.get("ghsa_id") or self._vuln.get("osv_id") or ""

                if vuln_id:
                    agent_cfg = getattr(self._config, 'agent', None)
                    protocol = getattr(agent_cfg, 'protocol', '') if agent_cfg else ''
                    model = getattr(agent_cfg, 'model', '') if agent_cfg else ''

                    # Save to database
                    repo.save_ai_analysis(
                        session, vuln_id, vuln_key,
                        self._full_response, protocol, model
                    )

                    # Save to file system
                    filepath = save_analysis(vuln_key, self._full_response, model)
                    analyses = list_analyses(vuln_key)

                    # Auto-watch
                    repo.update_status(session, vuln_id, "watched")
                    self._vuln["status"] = "watched"

                    self.thinking_output.append(
                        f"> 📌 已自动关注此漏洞\n"
                        f"> 💾 分析已保存至: data/analyses/{vuln_key}/\n"
                        f"> 📁 该漏洞共有 {len(analyses)} 份分析记录"
                    )
            finally:
                session.close()
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            self.thinking_output.append(f"> ⚠️ 保存失败: {e}")

    def _copy_result(self):
        if self._full_response:
            QApplication.clipboard().setText(self._full_response)
            self.btn_copy.setText("✅ 已复制")
            QTimer.singleShot(1500, lambda: self.btn_copy.setText("📋 复制"))

    def _on_close(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.terminate()
            self._worker.wait(1000)
        self.close()
