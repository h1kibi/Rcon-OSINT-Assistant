"""Agent worker — QThread wrapper for AgentService."""

from PySide6.QtCore import QThread, Signal


class AgentWorker(QThread):
    response_ready = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, agent_service, messages, parent=None):
        super().__init__(parent)
        self.agent_service = agent_service
        self.messages = messages

    def run(self):
        try:
            text = self.agent_service.answer_with_llm(self.messages)
            self.response_ready.emit(text)
        except Exception as e:
            self.error_occurred.emit(str(e))
