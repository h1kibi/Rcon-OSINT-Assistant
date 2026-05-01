import math
import random
from PySide6.QtCore import Qt, QPoint, Signal, QTimer
from PySide6.QtGui import (
    QPainter, QColor, QBrush, QPen, QFont, QRadialGradient,
    QLinearGradient, QPainterPath, QPolygon
)
from PySide6.QtWidgets import QWidget, QMenu, QApplication


class RobotOrb(QWidget):
    """Tactical reconnaissance AI robot floating orb."""

    open_main = Signal()
    refresh_now = Signal()
    toggle_pause = Signal()
    open_settings = Signal()
    quit_app = Signal()

    def __init__(self, parent=None, min_score: int = 70):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)

        self._min_score = min_score
        self._unread_count = 0
        self._paused = False
        self._hovered = False
        self._dragging = False
        self._drag_pos = None

        # Animation
        self._phase = 0.0
        self._blink_acc = 0.0
        self._blink_interval = random.uniform(5.0, 9.0)
        self._eye_open = 1.0
        self._is_blinking = False
        self._scan_line = 0.0

        self._margin = 12
        self._size = 80
        total = self._size + self._margin * 2
        self.setFixedSize(total, total)
        self.setMouseTracking(True)

        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)

    def set_unread_count(self, count: int):
        self._unread_count = count
        self.update()

    def set_paused(self, paused: bool):
        self._paused = paused
        self.update()

    def _tick(self):
        self._phase += 0.05
        self._scan_line = (self._scan_line + 0.015) % 1.0

        # Blink
        if not self._is_blinking:
            self._blink_acc += 0.033
            if self._blink_acc >= self._blink_interval:
                self._is_blinking = True
                self._blink_acc = 0.0
                self._blink_interval = random.uniform(5.0, 9.0)

        if self._is_blinking:
            self._eye_open -= 0.3
            if self._eye_open <= 0.0:
                self._eye_open = 0.0
                self._is_blinking = False
        else:
            self._eye_open = min(1.0, self._eye_open + 0.15)

        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        cx = self.width() / 2
        cy = self.height() / 2
        s = self._size
        hs = s / 2
        breath = 0.6 + 0.4 * math.sin(self._phase * 0.7)

        # ── Outer glow ──────────────────────────────────────────
        if self._hovered:
            glow_r = hs + 10
            glow = QRadialGradient(cx, cy, glow_r + 15)
            glow.setColorAt(0.0, QColor(0, 255, 65, int(50 * breath)))
            glow.setColorAt(0.5, QColor(0, 255, 65, int(20 * breath)))
            glow.setColorAt(1.0, QColor(0, 255, 65, 0))
            p.setBrush(QBrush(glow))
            p.setPen(Qt.NoPen)
            p.drawEllipse(int(cx - glow_r - 15), int(cy - glow_r - 15),
                          int((glow_r + 15) * 2), int((glow_r + 15) * 2))
        elif self._unread_count > 0 and not self._paused:
            glow_r = hs + 6
            pulse = 0.5 + 0.5 * math.sin(self._phase * 1.5)
            glow = QRadialGradient(cx, cy, glow_r + 10)
            glow.setColorAt(0.0, QColor(0, 255, 65, int(35 * pulse)))
            glow.setColorAt(1.0, QColor(0, 255, 65, 0))
            p.setBrush(QBrush(glow))
            p.setPen(Qt.NoPen)
            p.drawEllipse(int(cx - glow_r - 10), int(cy - glow_r - 10),
                          int((glow_r + 10) * 2), int((glow_r + 10) * 2))

        # ── Head (angular, tactical) ────────────────────────────
        hw = s * 0.46
        hh = s * 0.46

        # Shadow
        p.setBrush(QBrush(QColor(0, 0, 0, 50)))
        p.setPen(Qt.NoPen)
        self._draw_head_shape(p, cx + 1.5, cy + 2, hw, hh)

        # Head body - dark tactical armor
        head_grad = QLinearGradient(cx - hw, cy - hh, cx + hw, cy + hh)
        head_grad.setColorAt(0.0, QColor(28, 32, 38))
        head_grad.setColorAt(0.4, QColor(18, 21, 26))
        head_grad.setColorAt(1.0, QColor(12, 14, 18))
        p.setBrush(QBrush(head_grad))
        p.setPen(QPen(QColor(45, 50, 58), 1.5))
        self._draw_head_shape(p, cx, cy, hw, hh)

        # ── Visor / Faceplate ───────────────────────────────────
        visor_w = hw * 1.6
        visor_h = hh * 0.45
        visor_y = cy - visor_h * 0.3

        # Visor background
        p.setBrush(QBrush(QColor(5, 8, 12)))
        p.setPen(QPen(QColor(0, 255, 65, int(60 * breath)), 1))
        p.drawRoundedRect(
            int(cx - visor_w / 2), int(visor_y - visor_h / 2),
            int(visor_w), int(visor_h), 6, 6
        )

        # Scan line effect
        scan_y = visor_y - visor_h / 2 + visor_h * self._scan_line
        if not self._paused:
            p.setPen(QPen(QColor(0, 255, 65, int(40 * breath)), 1))
            p.drawLine(
                int(cx - visor_w / 2 + 3), int(scan_y),
                int(cx + visor_w / 2 - 3), int(scan_y)
            )

        # ── Eyes (angular, tactical) ────────────────────────────
        eye_y = visor_y - 2
        eye_spacing = visor_w * 0.28

        for side in [-1, 1]:
            ex = cx + side * eye_spacing

            # Right eye (with magnifier) - brighter, focused
            if side == 1:
                ew, eh = 14, 6
                brightness = 1.0
            else:
                # Left eye - slightly narrower, calmer
                ew, eh = 12, 5
                brightness = 0.85

            ew = int(ew * self._eye_open)
            if ew < 2:
                ew = 2
            eh = int(eh * self._eye_open)
            if eh < 2:
                eh = 2

            # Eye glow
            if not self._paused:
                glow_alpha = int(40 * breath * brightness)
                eye_glow = QRadialGradient(ex, eye_y, 16)
                eye_glow.setColorAt(0.0, QColor(0, 255, 65, glow_alpha))
                eye_glow.setColorAt(1.0, QColor(0, 255, 65, 0))
                p.setBrush(QBrush(eye_glow))
                p.setPen(Qt.NoPen)
                p.drawEllipse(int(ex - 16), int(eye_y - 16), 32, 32)

            # Eye shape (angular)
            intensity = int(220 * brightness * breath)
            if self._paused:
                intensity = 60
            eye_color = QColor(0, intensity, 50, 230)

            path = QPainterPath()
            path.moveTo(ex - ew / 2, eye_y)
            path.lineTo(ex - ew * 0.3, eye_y - eh / 2)
            path.lineTo(ex + ew * 0.3, eye_y - eh / 2)
            path.lineTo(ex + ew / 2, eye_y)
            path.lineTo(ex + ew * 0.3, eye_y + eh / 2)
            path.lineTo(ex - ew * 0.3, eye_y + eh / 2)
            path.closeSubpath()

            p.setBrush(QBrush(eye_color))
            p.setPen(Qt.NoPen)
            p.drawPath(path)

            # Eye center highlight
            if self._eye_open > 0.5 and not self._paused:
                p.setBrush(QBrush(QColor(200, 255, 200, int(120 * brightness))))
                p.drawEllipse(int(ex - 2), int(eye_y - 1), 4, 2)

        # ── Magnifying glass (over right eye) ───────────────────
        if not self._paused:
            mg_cx = cx + eye_spacing
            mg_cy = eye_y
            mg_r = 12

            # Glass frame
            p.setBrush(Qt.NoBrush)
            p.setPen(QPen(QColor(0, 255, 65, int(100 * breath)), 2))
            p.drawEllipse(int(mg_cx - mg_r), int(mg_cy - mg_r),
                          mg_r * 2, mg_r * 2)

            # Glass lens highlight
            p.setPen(QPen(QColor(0, 255, 65, int(30 * breath)), 1))
            p.drawEllipse(int(mg_cx - mg_r + 3), int(mg_cy - mg_r + 3),
                          (mg_r - 3) * 2, (mg_r - 3) * 2)

            # Handle
            hx = mg_cx + int(mg_r * 0.65)
            hy = mg_cy + int(mg_r * 0.65)
            p.setPen(QPen(QColor(0, 255, 65, int(80 * breath)), 2, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(hx, hy, hx + 10, hy + 10)

        # ── Mouth (tactical status bar) ─────────────────────────
        mouth_y = cy + hh * 0.5
        mouth_w = 20
        if not self._paused:
            mouth_alpha = int(120 * breath)
        else:
            mouth_alpha = 50

        # Three short dashes
        for i, dx in enumerate([-8, 0, 8]):
            a = mouth_alpha if i != 1 else int(mouth_alpha * 0.6)
            p.setPen(QPen(QColor(0, 255, 65, a), 2, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(int(cx + dx - 3), int(mouth_y), int(cx + dx + 3), int(mouth_y))

        # ── Forehead lines ──────────────────────────────────────
        for dx in [-16, 0, 16]:
            la = int(40 * breath)
            p.setPen(QPen(QColor(0, 255, 65, la), 1))
            p.drawLine(int(cx + dx - 4), int(cy - hh * 0.7),
                       int(cx + dx + 4), int(cy - hh * 0.7))

        # ── Badge ───────────────────────────────────────────────
        if self._unread_count > 0 and not self._paused:
            self._draw_badge(p, cx + hs - 2, cy - hs + 2)

        p.end()

    def _draw_head_shape(self, p, cx, cy, hw, hh):
        """Draw angular tactical head shape."""
        path = QPainterPath()
        # Angular head with slight taper at top
        path.moveTo(cx - hw * 0.8, cy + hh)  # bottom left
        path.lineTo(cx - hw, cy + hh * 0.3)  # left side
        path.lineTo(cx - hw * 0.85, cy - hh * 0.8)  # top left
        path.lineTo(cx - hw * 0.3, cy - hh)  # top left corner
        path.lineTo(cx + hw * 0.3, cy - hh)  # top right corner
        path.lineTo(cx + hw * 0.85, cy - hh * 0.8)  # top right
        path.lineTo(cx + hw, cy + hh * 0.3)  # right side
        path.lineTo(cx + hw * 0.8, cy + hh)  # bottom right
        path.closeSubpath()
        p.drawPath(path)

    def _draw_badge(self, p, bx, by):
        r = 12
        pulse = 0.7 + 0.3 * math.sin(self._phase * 2.5)
        alpha = int(255 * pulse)

        p.setBrush(QBrush(QColor(0, 0, 0, 40)))
        p.setPen(Qt.NoPen)
        p.drawEllipse(int(bx - r + 1), int(by - r + 1), r * 2, r * 2)

        p.setBrush(QBrush(QColor(200, 30, 30, alpha)))
        p.setPen(QPen(QColor(10, 15, 20), 2))
        p.drawEllipse(int(bx - r), int(by - r), r * 2, r * 2)

        p.setPen(QPen(QColor(255, 255, 255, alpha)))
        font = QFont("Consolas", 8)
        font.setBold(True)
        p.setFont(font)
        txt = str(self._unread_count) if self._unread_count <= 99 else "99+"
        p.drawText(int(bx - r), int(by - r * 0.5), r * 2, r, Qt.AlignCenter, txt)

    # ── Mouse Events ────────────────────────────────────────────
    def enterEvent(self, event):
        self._hovered = True
        self.setCursor(Qt.PointingHandCursor)

    def leaveEvent(self, event):
        self._hovered = False

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._dragging = True
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, event):
        if self._dragging and self._drag_pos:
            self.move(event.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            dist = 0
            if self._drag_pos:
                dist = (event.globalPosition().toPoint() -
                        self._drag_pos - self.frameGeometry().topLeft()).manhattanLength()
            self._dragging = False
            self._drag_pos = None
            if dist < 5:
                self.open_main.emit()

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background: #161b22; color: #c9d1d9;
                border: 1px solid #30363d; border-radius: 6px;
                padding: 4px; font-size: 12px;
            }
            QMenu::item { padding: 6px 16px; border-radius: 4px; }
            QMenu::item:selected { background: #1f6feb; }
            QMenu::separator { height: 1px; background: #30363d; margin: 4px 8px; }
        """)
        items = [
            ("打开面板", self.open_main),
            ("立即同步", self.refresh_now),
            ("恢复采集" if self._paused else "暂停采集", self.toggle_pause),
            None,
            ("设置", self.open_settings),
            None,
            ("退出程序", self.quit_app),
        ]
        for item in items:
            if item is None:
                menu.addSeparator()
            else:
                text, signal = item
                action = QAction(text, self)
                action.triggered.connect(signal.emit)
                menu.addAction(action)
        menu.exec(event.globalPos())
