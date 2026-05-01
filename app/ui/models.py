from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtGui import QColor, QBrush, QFont


class VulnerabilityTableModel(QAbstractTableModel):
    """Table model for vulnerability list."""

    HEADERS = [
        "CVE ID", "漏洞标题", "等级", "CVSS", "EPSS", "评分", "状态",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: list[dict] = []

    def set_data(self, data: list[dict]):
        self.beginResetModel()
        self._data = data
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        row = self._data[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._get_display_value(row, col)

        if role == Qt.ForegroundRole:
            return self._get_foreground(row, col)

        if role == Qt.BackgroundRole:
            return self._get_background(row)

        if role == Qt.ToolTipRole:
            return self._get_tooltip(row, col)

        if role == Qt.FontRole:
            if col == 5:  # Score bold
                font = QFont()
                font.setBold(True)
                return font

        return None

    def _get_display_value(self, row: dict, col: int) -> str:
        if col == 0:
            return row.get("cve_id") or row.get("ghsa_id") or row.get("osv_id") or ""
        if col == 1:
            title = row.get("title", "")
            tags = []
            if row.get("is_kev"):
                tags.append("[KEV]")
            if row.get("has_poc_signal"):
                tags.append("[PoC]")
            if row.get("has_patch"):
                tags.append("[补丁]")
            tag_str = " ".join(tags)
            if tag_str:
                return f"{tag_str} {title}"
            return title
        if col == 2:
            return row.get("severity", "UNKNOWN")
        if col == 3:
            val = row.get("cvss_score")
            return f"{val:.1f}" if val is not None else "-"
        if col == 4:
            val = row.get("epss_percentile")
            return f"{val * 100:.0f}%" if val is not None else "-"
        if col == 5:
            val = row.get("action_value_score")
            return f"{val:.0f}" if val is not None else "0"
        if col == 6:
            status_map = {"unread": "未读", "read": "已读", "watched": "关注", "ignored": "忽略"}
            return status_map.get(row.get("status", ""), "")

        return ""

    def _get_tooltip(self, row: dict, col: int) -> str:
        if col == 1:
            desc = row.get("description", "")
            if len(desc) > 200:
                return desc[:200] + "..."
            return desc
        return ""

    def _get_foreground(self, row: dict, col: int):
        # Ignored items: dim everything
        if row.get("status") == "ignored":
            return QBrush(QColor("#484f58"))

        if col == 0:
            return QBrush(QColor("#58a6ff"))

        if col == 2:
            sev = (row.get("severity") or "").upper()
            colors = {
                "CRITICAL": QColor("#f85149"),
                "HIGH": QColor("#d29922"),
                "MEDIUM": QColor("#58a6ff"),
                "LOW": QColor("#3fb950"),
            }
            return QBrush(colors.get(sev, QColor("#8b949e")))

        if col == 5:
            score = row.get("action_value_score", 0) or 0
            if score >= 80:
                return QBrush(QColor("#f85149"))
            elif score >= 60:
                return QBrush(QColor("#d29922"))
            elif score >= 40:
                return QBrush(QColor("#58a6ff"))
            return QBrush(QColor("#484f58"))

        if col == 6:
            status = row.get("status", "")
            colors = {
                "unread": QColor("#58a6ff"),
                "read": QColor("#484f58"),
                "watched": QColor("#d29922"),
                "ignored": QColor("#484f58"),
            }
            return QBrush(colors.get(status, QColor("#c9d1d9")))

        if col == 1:
            title = row.get("title", "")
            if "[KEV]" in title or "[PoC]" in title:
                return QBrush(QColor("#d29922"))

        return QBrush(QColor("#c9d1d9"))

    def _get_background(self, row: dict):
        score = row.get("action_value_score", 0) or 0
        if score >= 80:
            return QBrush(QColor("#f8514912"))
        if row.get("is_kev"):
            return QBrush(QColor("#f8514908"))
        return None

    def get_vuln_id(self, row_index: int) -> int:
        if 0 <= row_index < len(self._data):
            return self._data[row_index].get("id", 0)
        return 0
