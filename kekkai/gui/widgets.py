"""Small themed components and native charts; no scan logic."""

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap, QBitmap, QRegion
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget, QPushButton, QScrollArea

from ..themes import tokens
from ..branding import ASSETS
from ..i18n import tr

ICON_PATHS = {
    'yara_rules':'<path d="M4 3h12l4 4v14H4zM8 10h8M8 14h8M8 18h5"/>',
    "home": '<path d="M3 11l9-8 9 8v10H3z"/><path d="M9 21v-7h6v7"/>',
    "scan": '<circle cx="10" cy="10" r="6"/><path d="M15 15l6 6M7 10h6M10 7v6"/>',
    "projects": '<path d="M3 6h7l2 3h9v12H3z"/>',
    "reports": '<path d="M6 3h9l4 4v14H6zM10 11h5M10 15h5M15 3v5h4"/>',
    "scanners": '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
    "ai": '<path d="M12 3l2 6 7 3-7 2-2 7-3-7-6-2 6-3z"/>',
    "settings": '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
    "about": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7v1"/>',
    "dashboard": '<path d="M4 20V4M4 20h17M8 16l4-5 4 2 5-7"/>',
    "play": '<path d="M7 4l14 8-14 8z"/>',
    "folder": '<path d="M3 6h7l2 3h9v12H3z"/>',
}


def icon(name: str, color: str) -> QIcon:
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="none" stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{ICON_PATHS[name]}</g></svg>'
    pixmap = QPixmap(48, 48)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    QSvgRenderer(svg.encode()).render(painter)
    painter.end()
    return QIcon(pixmap)


def logo(theme="dark", size=44) -> QPixmap:
    pixmap = QPixmap(str(ASSETS / "logo.png"))
    bounds = QRegion(QBitmap.fromImage(pixmap.toImage().createAlphaMask())).boundingRect()
    if not bounds.isEmpty():
        pixmap = pixmap.copy(bounds)
    pixmap = pixmap.scaled(size*2, size*2, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
    pixmap.setDevicePixelRatio(2)
    return pixmap


def wordmark(width=175):
    pixmap = QPixmap(str(ASSETS / "logo+nome.png"))
    bounds = QRegion(QBitmap.fromImage(pixmap.toImage().createAlphaMask())).boundingRect()
    if not bounds.isEmpty():
        pixmap = pixmap.copy(bounds)
    pixmap = pixmap.scaledToWidth(width*2, Qt.TransformationMode.SmoothTransformation)
    pixmap.setDevicePixelRatio(2)
    return pixmap


def label(text: str, role=None, *, wrap=False) -> QLabel:
    widget = QLabel(tr(text))
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(wrap)
    if role:
        widget.setProperty("role", role)
    return widget


def button(text: str, callback=None, *, primary=False, name=None) -> QPushButton:
    widget = QPushButton(tr(text))
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    widget.setProperty("primary", primary)
    if name:
        widget.setObjectName(name)
    if callback:
        widget.clicked.connect(callback)
    return widget


class Card(QFrame):
    def __init__(self, title=None, parent=None):
        super().__init__(parent)
        self.setProperty("card", True)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(22, 20, 22, 20)
        self.body.setSpacing(12)
        if title:
            self.body.addWidget(label(title, "heading"))


def scroll_page() -> tuple[QScrollArea, QWidget, QVBoxLayout]:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    content = QWidget()
    layout = QVBoxLayout(content)
    layout.setContentsMargins(26, 22, 26, 26)
    layout.setSpacing(20)
    scroll.setWidget(content)
    return scroll, content, layout


class ScanChart(QWidget):
    def __init__(self, mode: str, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.theme = "dark"
        self.summary = {}
        self.setMinimumHeight(215)
        self.setAccessibleName(tr("Findings por severidade") if mode == "severity" else tr("Tempo por scanner"))

    def update_data(self, summary, theme):
        self.summary, self.theme = summary or {}, theme
        self.update()

    def paintEvent(self, event):
        colors = tokens(self.theme)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(QFont("Segoe UI", 9))
        if not self.summary:
            painter.setPen(QColor(colors["muted"]))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, tr("Execute um scan para visualizar os indicadores"))
            painter.end()
            return
        if self.mode == "severity":
            data = [(name, self.summary.get("totals", {}).get(key, 0)) for name, key in
                    [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]]
            data.extend([("Warn", sum(f.get("severity") == "WARN" for f in self.summary.get("findings", []))),
                         ("Info", self.summary.get("totals", {}).get("info", 0))])
            maximum = max([value for _, value in data] + [1])
            width = (self.width() - 35) / len(data)
            baseline = self.height() - 34
            for index, (name, value) in enumerate(data):
                height = value / maximum * (self.height() - 72)
                x = 18 + index * width
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(colors[f"chart-{index % 4 + 1}"]))
                painter.drawRoundedRect(QRectF(x + width * .28, baseline - height, width * .44, max(2, height)), 5, 5)
                painter.setPen(QColor(colors["text-secondary"]))
                painter.drawText(QRectF(x, baseline + 9, width, 24), Qt.AlignmentFlag.AlignCenter, name)
                painter.drawText(QRectF(x, baseline - height - 26, width, 23), Qt.AlignmentFlag.AlignCenter, str(value))
        else:
            names = ["semgrep", "gitleaks", "sca", "yara", "owasp", "zap", "ai"]
            durations = [self.summary.get("scanners", {}).get(name, {}).get("duration_seconds", 0) for name in names]
            maximum = max(durations + [1])
            for index, name in enumerate(names):
                y = index * 29 + 5
                painter.setPen(QColor(colors["text-secondary"]))
                painter.drawText(QRectF(0, y, 78, 24), Qt.AlignmentFlag.AlignVCenter, name.upper() if name in {"sca", "yara", "owasp", "zap", "ai"} else name.title())
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(colors[f"chart-{index % 2 + 1}"]))
                painter.drawRoundedRect(QRectF(82, y + 5, max(2, durations[index] / maximum * (self.width() - 148)), 13), 4, 4)
                painter.setPen(QColor(colors["text-secondary"]))
                painter.drawText(QRectF(self.width() - 60, y, 58, 24), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, f"{durations[index]:.1f}s")
        painter.end()
