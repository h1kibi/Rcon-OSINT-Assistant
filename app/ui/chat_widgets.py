"""Chat message widgets: ChatMessageWidget, ChatComposer, render_markdown."""

from PySide6.QtCore import Qt, Signal, QEvent
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QVBoxLayout, QLabel,
    QTextBrowser, QPushButton, QTextEdit, QSizePolicy,
)
from PySide6.QtGui import QFont


def render_markdown(widget, text: str):
    text = text or ""
    if hasattr(widget, "setMarkdown"):
        try:
            widget.setMarkdown(text)
            return
        except Exception:
            pass
    try:
        import markdown
        html = markdown.markdown(
            text,
            extensions=["fenced_code", "tables", "nl2br"],
            output_format="html5",
        )
        widget.setHtml(html)
    except Exception:
        widget.setPlainText(text)


class ChatMessageWidget(QFrame):
    def __init__(self, role: str, parent=None):
        super().__init__(parent)
        self.role = role
        self._raw_text = ""
        self.setObjectName("chatMessage")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(28, 6, 28, 6)
        outer.setSpacing(10)

        self.avatar = QLabel("R" if role == "assistant" else "你")
        self.avatar.setFixedSize(30, 30)
        self.avatar.setAlignment(Qt.AlignCenter)
        self.avatar.setObjectName("assistantAvatar" if role == "assistant" else "userAvatar")

        self.bubble = QFrame()
        self.bubble.setObjectName("assistantBubble" if role == "assistant" else "userBubble")
        self.bubble.setMaximumWidth(820)

        bubble_l = QVBoxLayout(self.bubble)
        bubble_l.setContentsMargins(16, 12, 16, 12)
        bubble_l.setSpacing(8)

        self.body = QTextBrowser()
        self.body.setOpenExternalLinks(True)
        self.body.setFrameShape(QFrame.NoFrame)
        self.body.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.body.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.body.setObjectName("messageBody")
        self.body.setFont(QFont("Microsoft YaHei", 10))
        self.body.setMinimumHeight(36)
        bubble_l.addWidget(self.body)

        if role == "user":
            outer.addStretch(1)
            outer.addWidget(self.bubble, 0)
            outer.addWidget(self.avatar, 0, Qt.AlignTop)
        else:
            self.bubble.setMaximumWidth(820)
            outer.addWidget(self.avatar, 0, Qt.AlignTop)
            outer.addWidget(self.bubble, 0)
            outer.addStretch(1)

        if role == "user":
            self.bubble.setMaximumWidth(680)

    def set_text(self, text: str, markdown: bool = True):
        self._raw_text = text or ""
        if markdown:
            render_markdown(self.body, self._raw_text)
        else:
            self.body.setPlainText(self._raw_text)
        doc_height = int(self.body.document().size().height()) + 6
        self.body.setFixedHeight(max(36, doc_height))

    def append_text(self, chunk: str):
        self.set_text(self._raw_text + chunk)


class ChatComposer(QFrame):
    submitted = Signal(str)
    stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("composerShell")
        self.setProperty("focused", False)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 10, 10)
        layout.setSpacing(10)

        self.input = QTextEdit()
        self.input.setObjectName("composerInput")
        self.input.setPlaceholderText("询问漏洞、CVE、KEV、EPSS 或让 Rcon 总结风险...")
        self.input.setFixedHeight(48)
        self.input.installEventFilter(self)
        layout.addWidget(self.input, 1)

        self.send_btn = QPushButton("↑")
        self.send_btn.setObjectName("sendCircle")
        self.send_btn.setFixedSize(38, 38)
        self.send_btn.clicked.connect(self._emit_submit)
        layout.addWidget(self.send_btn)

    def _emit_submit(self):
        text = self.input.toPlainText().strip()
        if not text:
            return
        self.input.clear()
        self.submitted.emit(text)

    def set_generating(self, generating: bool):
        self.send_btn.setText("■" if generating else "↑")

    def eventFilter(self, obj, event):
        if obj is self.input:
            if event.type() == QEvent.Type.FocusIn:
                self._set_focused(True)
            elif event.type() == QEvent.Type.FocusOut:
                self._set_focused(False)
            elif event.type() == QEvent.Type.KeyPress:
                if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                    if event.modifiers() & Qt.ShiftModifier:
                        return False
                    self._emit_submit()
                    return True
        return super().eventFilter(obj, event)

    def _set_focused(self, focused: bool):
        if self.property("focused") == focused:
            return
        self.setProperty("focused", focused)
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()
