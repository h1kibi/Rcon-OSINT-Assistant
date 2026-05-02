"""Font loading and helpers for pixel-hacker terminal theme."""

from PySide6.QtGui import QFont, QFontDatabase

PIXEL_FONT_FAMILY = "Consolas"
MONO_FONT_FAMILY = "Consolas"
TEXT_FONT_FAMILY = "Microsoft YaHei UI"


def load_ui_fonts():
    global PIXEL_FONT_FAMILY, MONO_FONT_FAMILY

    font_path = "assets/fonts/FusionPixel-12px-monospaced-zh_hans.ttf"
    font_id = QFontDatabase.addApplicationFont(font_path)

    if font_id != -1:
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            PIXEL_FONT_FAMILY = families[0]
            MONO_FONT_FAMILY = families[0]


def pixel_font(size: int = 10, bold: bool = False) -> QFont:
    font = QFont(PIXEL_FONT_FAMILY, size)
    font.setBold(bold)
    return font


def mono_font(size: int = 10, bold: bool = False) -> QFont:
    font = QFont(MONO_FONT_FAMILY, size)
    font.setBold(bold)
    return font


def text_font(size: int = 10, bold: bool = False) -> QFont:
    font = QFont(TEXT_FONT_FAMILY, size)
    font.setBold(bold)
    return font
