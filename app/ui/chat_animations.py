"""Chat animations: fade/slide in, smooth scroll, typewriter renderer."""

from PySide6.QtCore import (
    QPropertyAnimation, QEasingCurve, QPoint, QParallelAnimationGroup, QObject, QTimer, Signal,
)
from PySide6.QtWidgets import QGraphicsOpacityEffect


def animate_message_in(widget, dy: int = 10, duration: int = 180):
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(0.0)
    widget.setGraphicsEffect(effect)

    start_pos = widget.pos() + QPoint(0, dy)
    end_pos = widget.pos()
    widget.move(start_pos)

    opacity = QPropertyAnimation(effect, b"opacity", widget)
    opacity.setStartValue(0.0)
    opacity.setEndValue(1.0)
    opacity.setDuration(duration)
    opacity.setEasingCurve(QEasingCurve.Type.OutCubic)

    slide = QPropertyAnimation(widget, b"pos", widget)
    slide.setStartValue(start_pos)
    slide.setEndValue(end_pos)
    slide.setDuration(duration)
    slide.setEasingCurve(QEasingCurve.Type.OutCubic)

    group = QParallelAnimationGroup(widget)
    group.addAnimation(opacity)
    group.addAnimation(slide)
    group.start()
    widget._entry_anim = group


def smooth_scroll_to_bottom(scroll_area, duration: int = 120):
    bar = scroll_area.verticalScrollBar()
    old = getattr(scroll_area, "_scroll_anim", None)
    if old and old.state() == QPropertyAnimation.State.Running:
        old.stop()
    anim = QPropertyAnimation(bar, b"value", scroll_area)
    anim.setStartValue(bar.value())
    anim.setEndValue(bar.maximum())
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.start()
    scroll_area._scroll_anim = anim


class TypewriterRenderer(QObject):
    finished = Signal()

    def __init__(self, target_message, parent=None):
        super().__init__(parent)
        self.target = target_message
        self.buffer = ""
        self.visible = ""
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._flush)

    def start(self):
        self.buffer = ""
        self.visible = ""
        self.target.set_text("")
        self.timer.start(16)

    def feed(self, text: str):
        self.buffer += text or ""

    def finish(self):
        self._flush(all_remaining=True)
        self.timer.stop()
        self.target.set_text(self.visible, markdown=True)
        self.finished.emit()

    def _flush(self, all_remaining: bool = False):
        if not self.buffer:
            return
        n = len(self.buffer) if all_remaining else min(8, len(self.buffer))
        chunk = self.buffer[:n]
        self.buffer = self.buffer[n:]
        self.visible += chunk
        self.target.set_text(self.visible, markdown=False)
