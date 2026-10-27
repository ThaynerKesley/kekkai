"""Small themed components and native charts; no scan logic."""

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap, QBitmap, QRegion, QPen, QPainterPath, QLinearGradient, QBrush
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QFrame, QLabel, QVBoxLayout, QWidget, QPushButton, QScrollArea,
    QStyledItemDelegate, QStyleOptionViewItem, QStyle, QGraphicsDropShadowEffect)

from ..themes import tokens
from ..skins import get_skin
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
    "blocked": '<circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/>',
    "radar": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 1v3M12 20v3M1 12h3M20 12h3"/>',
    "full_scan": '<path d="M3 8V3h5M16 3h5v5M21 16v5h-5M8 21H3v-5"/><rect x="8" y="8" width="8" height="8" rx="1"/>',
    "chevron_down": '<path d="M5 9l7 7 7-7"/>',
    "status_dot": '<circle cx="12" cy="12" r="3" stroke-width="6"/>',
}


def icon(name: str, color: str) -> QIcon:
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="none" stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{ICON_PATHS[name]}</g></svg>'
    pixelated = get_skin().monochrome
    pixmap = QPixmap(24, 24) if pixelated else QPixmap(48, 48)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    QSvgRenderer(svg.encode()).render(painter)
    painter.end()
    if pixelated:
        pixmap = pixmap.scaled(48, 48, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.FastTransformation)
    return QIcon(pixmap)


def logo(theme="dark", size=44) -> QPixmap:
    skin = get_skin()
    pixmap = QPixmap(str(skin.icon))
    bounds = QRegion(QBitmap.fromImage(pixmap.toImage().createAlphaMask())).boundingRect()
    if not bounds.isEmpty():
        pixmap = pixmap.copy(bounds)
    if skin.icon == skin.wordmark:
        # Wide supplied artwork places the compact mark on its left.
        width = min(pixmap.width(), round(pixmap.height() * skin.mark_aspect))
        pixmap = pixmap.copy(0, 0, width, pixmap.height())
    transformation = Qt.TransformationMode.FastTransformation if skin.monochrome else Qt.TransformationMode.SmoothTransformation
    pixmap = pixmap.scaled(size*2, size*2, Qt.AspectRatioMode.KeepAspectRatio, transformation)
    pixmap.setDevicePixelRatio(2)
    return pixmap


def wordmark(width=175):
    skin = get_skin()
    pixmap = QPixmap(str(skin.wordmark))
    bounds = QRegion(QBitmap.fromImage(pixmap.toImage().createAlphaMask())).boundingRect()
    if not bounds.isEmpty():
        pixmap = pixmap.copy(bounds)
    transformation = Qt.TransformationMode.FastTransformation if skin.monochrome else Qt.TransformationMode.SmoothTransformation
    pixmap = pixmap.scaledToWidth(width*2, transformation)
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
        self.theme = "dark"
        hard_shadow(self)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(20, 18, 20, 18)
        self.body.setSpacing(12)
        if title:
            self.body.addWidget(label(title, "card-title"))

    def paintEvent(self, event):
        super().paintEvent(event)
        if get_skin().monochrome:
            painter = QPainter(self)
            painter.setPen(QColor(tokens(self.theme)["border"]))
            # A fine etched header band, without imitating window controls.
            for y in (6, 9):
                painter.drawLine(6, y, self.width() - 7, y)
            painter.end()
            return
        if not get_skin().hardware:
            return
        colors = tokens(self.theme)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor(colors["bolt"]), 1))
        painter.setBrush(QColor(colors["bolt-fill"]))
        for x, y in ((9, 9), (self.width() - 10, 9), (9, self.height() - 10),
                     (self.width() - 10, self.height() - 10)):
            painter.drawEllipse(QRectF(x - 3, y - 3, 6, 6))
            painter.drawLine(x - 1, y + 1, x + 1, y - 1)
        painter.end()

    def set_theme(self, theme):
        self.theme = theme
        self.update()


def hard_shadow(widget):
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(0)
    shadow.setOffset(4, 5)
    shadow.setColor(QColor(tokens("dark")["shadow"]))
    widget.setGraphicsEffect(shadow)
    return shadow


class SkinCanvas(QFrame):
    """Use the skin's wallpaper without replacing working application controls."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.theme = "dark"
        self.grain = QPixmap(64, 64)
        self.crt_wallpaper = QPixmap()
        self.set_theme(self.theme)

    def set_theme(self, theme):
        self.theme = theme
        self.crt_wallpaper = QPixmap()
        self.grain.fill(Qt.GlobalColor.transparent)
        painter = QPainter(self.grain)
        color = QColor(tokens(theme)["shadow"])
        color.setAlpha(12)
        painter.setPen(color)
        for index in range(120):
            painter.drawPoint((index * 17) % 64, (index * 29 + index // 4) % 64)
        painter.end()
        self.update()

    def monochrome_wallpaper(self):
        """Cache static dithered ridges at the current size; no per-frame texture work."""
        if self.crt_wallpaper.size() != self.size():
            colors = tokens(self.theme)
            self.crt_wallpaper = QPixmap(self.size())
            self.crt_wallpaper.fill(QColor(colors["background"]))
            painter = QPainter(self.crt_wallpaper)
            w, h = self.width(), self.height()
            for points, pattern in (
                (((0, .83), (.12, .71), (.22, .76), (.37, .52), (.44, .64),
                  (.53, .44), (.64, .67), (.78, .57), (.87, .71), (1, .60)), Qt.BrushStyle.Dense6Pattern),
                (((0, .94), (.16, .83), (.27, .87), (.42, .73), (.56, .86),
                  (.69, .70), (.82, .87), (1, .78)), Qt.BrushStyle.Dense4Pattern),
            ):
                ridge = QPainterPath()
                ridge.moveTo(0, h)
                for x, y in points:
                    ridge.lineTo(round(x * w), round(y * h))
                ridge.lineTo(w, h)
                ridge.closeSubpath()
                painter.fillPath(ridge, QBrush(QColor(colors["wallpaper-wave"]), pattern))
            painter.end()
        return self.crt_wallpaper

    def paintEvent(self, event):
        super().paintEvent(event)
        if get_skin().monochrome:
            painter = QPainter(self)
            painter.setClipRect(self.rect().adjusted(3, 3, -3, -3))
            painter.drawPixmap(0, 0, self.monochrome_wallpaper())
            painter.end()
            return
        if not (get_skin().paper or get_skin().hardware):
            return
        colors = tokens(self.theme)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        clip = QPainterPath()
        clip.addRoundedRect(QRectF(self.rect()).adjusted(2, 2, -2, -2), 10, 10)
        painter.setClipPath(clip)
        painter.fillRect(self.rect(), QColor(colors["background"]))
        if get_skin().hardware:
            painter.setPen(QPen(QColor(colors["border"]), 1))
            for y in range(18, self.height() - 12, 6):
                painter.drawLine(4, y, 9, y)
                painter.drawLine(self.width() - 10, y, self.width() - 5, y)
            painter.drawTiledPixmap(self.rect(), self.grain)
            painter.end()
            return
        w, h = self.width(), self.height()
        ribbon = QPainterPath()
        ribbon.moveTo(0, .10 * h)
        ribbon.cubicTo(.25 * w, .25 * h, .55 * w, -.18 * h, w, .13 * h)
        ribbon.lineTo(w, .46 * h)
        ribbon.cubicTo(.7 * w, .18 * h, .3 * w, .66 * h, 0, .36 * h)
        ribbon.closeSubpath()
        ribbon.moveTo(0, .68 * h)
        ribbon.cubicTo(.35 * w, .55 * h, .5 * w, 1.08 * h, w, .9 * h)
        ribbon.lineTo(w, h)
        ribbon.lineTo(0, h)
        ribbon.closeSubpath()
        painter.fillPath(ribbon, QColor(colors["wallpaper-wave"]))
        painter.drawTiledPixmap(self.rect(), self.grain)
        painter.end()


class IconTile(QWidget):
    """Small painted icon tile; no blur layers or animation in the render path."""
    def __init__(self, symbol: str, tone="violet", size=64, parent=None):
        super().__init__(parent)
        self.symbol, self.tone, self.theme = symbol, tone, "dark"
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.glyph = icon(symbol, tokens(self.theme)["tile-ink"])

    def set_theme(self, theme):
        self.theme = theme
        self.glyph = icon(self.symbol, tokens(theme)["tile-ink"])
        self.update()

    def paintEvent(self, event):
        colors = tokens(self.theme)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(5, 5, -5, -5)
        edge = QColor(colors["tile-" + self.tone + "-edge"])
        if get_skin().monochrome:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
            painter.setPen(QPen(edge, 2))
            painter.setBrush(QColor(colors["tile-" + self.tone]))
            painter.drawRect(rect)
            painter.setPen(QPen(edge, 1))
            painter.drawRect(rect.adjusted(4, 4, -4, -4))
        elif get_skin().hardware:
            painter.setPen(QPen(QColor(colors["border-light"]), 2))
            painter.setBrush(QColor(colors["screen-deep"]))
            painter.drawRect(rect)
            inner = rect.adjusted(3, 3, -3, -3)
            gradient = QLinearGradient(inner.topLeft(), inner.bottomLeft())
            gradient.setColorAt(0, QColor(colors["screen-bg"]))
            gradient.setColorAt(1, QColor(colors["screen-deep"]))
            painter.fillRect(inner, gradient)
            line = QColor(colors["screen-line"])
            line.setAlpha(35)
            painter.setPen(line)
            for y in range(int(inner.top()) + 2, int(inner.bottom()), 4):
                painter.drawLine(int(inner.left()), y, int(inner.right()), y)
        elif get_skin().paper:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(colors["shadow"]))
            painter.drawRoundedRect(rect.translated(2, 3), 6, 6)
            painter.setBrush(QColor(colors["tile-" + self.tone]))
            painter.setPen(QPen(edge, 2))
            painter.drawRoundedRect(rect, 6, 6)
        else:
            for expansion, alpha in [(4, 14), (2, 25)]:
                glow = QColor(edge)
                glow.setAlpha(alpha)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(glow)
                painter.drawRoundedRect(rect.adjusted(-expansion, -expansion, expansion, expansion), 13, 13)
            gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
            gradient.setColorAt(0, QColor(colors["tile-" + self.tone]))
            gradient.setColorAt(1, QColor(colors["tile-" + self.tone + "-end"]))
            painter.setBrush(gradient)
            painter.setPen(QPen(edge, 1))
            painter.drawRoundedRect(rect, 11, 11)
        glyph = rect.adjusted(13, 13, -13, -13).toRect()
        self.glyph.paint(painter, glyph)
        painter.end()


class StatusBadgeDelegate(QStyledItemDelegate):
    """Paint status badges while retaining table text, selection and keyboard access."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.theme = "dark"

    def paint(self, painter, option, index):
        text = index.data(Qt.ItemDataRole.DisplayRole)
        if text not in {"COMPLETED", "SKIPPED"}:
            super().paint(painter, option, index)
            return
        colors = tokens(self.theme)
        color = QColor(colors["success"] if text == "COMPLETED" else colors["muted"])
        flat = get_skin().paper or get_skin().hardware or get_skin().monochrome
        if flat:
            background = QColor(colors["badge-success"] if text == "COMPLETED" else colors["badge-muted"])
        else:
            background = QColor(color)
            background.setAlpha(28)
        base = QStyleOptionViewItem(option)
        self.initStyleOption(base, index)
        base.text = ""
        style = option.widget.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, base, painter, option.widget)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(option.font)
        width = min(option.rect.width() - 12, painter.fontMetrics().horizontalAdvance(text) + 16)
        rect = QRectF(option.rect.left() + 8, option.rect.center().y() - 11, width, 23)
        painter.setPen(QPen(QColor(colors["border"]), 1) if flat else Qt.PenStyle.NoPen)
        painter.setBrush(background)
        radius = 0 if get_skin().monochrome else 3
        painter.drawRoundedRect(rect, radius, radius)
        painter.setPen(color)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()


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
        self.setMinimumHeight(160)
        self.setAccessibleName(tr("Findings por severidade") if mode == "severity" else tr("Tempo por scanner"))

    def update_data(self, summary, theme):
        self.summary, self.theme = summary or {}, theme
        if self.summary:
            if self.mode == "severity":
                values = self.severity_data()
                description = "; ".join(f"{name}: {value}" for name, value in values)
            else:
                description = "; ".join(f"{name}: {self.summary.get('scanners', {}).get(name, {}).get('duration_seconds', 0):.1f}s"
                                        for name in ("semgrep", "gitleaks", "sca", "yara", "owasp", "zap", "ai"))
        else:
            description = tr("Execute um scan para visualizar os indicadores")
        self.setAccessibleDescription(description)
        self.update()

    def severity_data(self):
        data = [(name, self.summary.get("totals", {}).get(key, 0)) for name, key in
                [(tr("Críticos"), "critical"), (tr("Altos"), "high"), (tr("Médios"), "medium"), (tr("Baixos"), "low")]]
        data.extend([("Warn", sum(f.get("severity") == "WARN" for f in self.summary.get("findings", []))),
                     ("Info", self.summary.get("totals", {}).get("info", 0))])
        return data

    def draw_bar(self, painter, rect, color):
        if get_skin().monochrome:
            painter.setPen(QPen(QColor(tokens(self.theme)["text-primary"]), 1))
            painter.setBrush(QBrush(color, Qt.BrushStyle.Dense4Pattern))
            radius = 0
        elif get_skin().hardware:
            painter.setPen(QPen(QColor(tokens(self.theme)["screen-line"]), 1))
            fill = QColor(color)
            fill.setAlpha(185)
            painter.setBrush(fill)
            radius = 0
        elif get_skin().paper:
            painter.setPen(QPen(QColor(tokens(self.theme)["border"]), 1.5))
            painter.setBrush(color)
            radius = 2
        else:
            gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
            gradient.setColorAt(0, color.lighter(117))
            gradient.setColorAt(1, color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(gradient)
            radius = 4
        painter.drawRoundedRect(rect, radius, radius)

    def paintEvent(self, event):
        colors = tokens(self.theme)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(QFont(colors["font-body"], 9))
        if get_skin().monochrome:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
            painter.fillRect(self.rect(), QColor(colors["surface-raised"]))
            colors["surface"] = colors["surface-raised"]
            painter.setPen(QPen(QColor(colors["border"]), 1))
            painter.drawRect(self.rect().adjusted(0, 0, -1, -1))
        if get_skin().hardware:
            colors.update({"surface": colors["screen-bg"], "grid": colors["screen-grid"],
                           "text-secondary": colors["screen-text"], "muted": colors["screen-muted"]})
            painter.fillRect(self.rect(), QColor(colors["screen-bg"]))
            painter.setPen(QPen(QColor(colors["screen-deep"]), 2))
            painter.drawRect(self.rect().adjusted(1, 1, -1, -1))
            scanline = QColor(colors["screen-line"])
            scanline.setAlpha(25)
            painter.setPen(scanline)
            for y in range(4, self.height() - 2, 4):
                painter.drawLine(2, y, self.width() - 3, y)
            painter.setPen(QPen(QColor(colors["grid"]), 1))
            for x in range(32, self.width() - 8, 32):
                painter.drawLine(x, 3, x, self.height() - 4)
        if not self.summary:
            painter.setPen(QPen(QColor(colors["grid"]), 1, Qt.PenStyle.DotLine))
            for row in range(4):
                y = 20 + row * (self.height() - 50) / 3
                painter.drawLine(12, int(y), self.width() - 12, int(y))
            painter.setPen(QColor(colors["muted"]))
            inset = 1 if get_skin().monochrome else 0
            painter.fillRect(QRectF(inset, self.height() / 2 - 24, self.width() - 2 * inset, 48), QColor(colors["surface"]))
            painter.drawText(self.rect().adjusted(16, 0, -16, 0), Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                             tr("Execute um scan para visualizar os indicadores"))
            painter.end()
            return
        if self.mode == "severity":
            data = self.severity_data()
            maximum = max([value for _, value in data] + [1])
            step = max(1, -(-maximum // 4))
            maximum = step * 4
            width = (self.width() - 38) / len(data)
            baseline = self.height() - 30
            plot_height = self.height() - 54
            for row in range(5):
                y = baseline - row / 4 * plot_height
                painter.setPen(QPen(QColor(colors["grid"]), 1, Qt.PenStyle.DotLine))
                painter.drawLine(30, int(y), self.width() - 5, int(y))
                painter.setPen(QColor(colors["muted"]))
                painter.drawText(QRectF(0, y - 10, 23, 20), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(row * step))
            for index, (name, value) in enumerate(data):
                height = value / maximum * plot_height
                x = 32 + index * width
                color = QColor(colors[f"chart-{index + 1}"])
                self.draw_bar(painter, QRectF(x + width * .23, baseline - max(2, height), width * .54, max(2, height)), color)
                painter.setPen(QColor(colors["text-secondary"]))
                painter.drawText(QRectF(x, baseline + 9, width, 24), Qt.AlignmentFlag.AlignCenter, name)
                painter.drawText(QRectF(x, baseline - height - 26, width, 23), Qt.AlignmentFlag.AlignCenter, str(value))
        else:
            names = ["semgrep", "gitleaks", "sca", "yara", "owasp", "zap", "ai"]
            durations = [self.summary.get("scanners", {}).get(name, {}).get("duration_seconds", 0) for name in names]
            maximum = max(durations + [1])
            for index, name in enumerate(names):
                y = index * ((self.height() - 6) / 7) + 2
                painter.setPen(QColor(colors["text-secondary"]))
                inset = 8 if get_skin().hardware or get_skin().monochrome else 0
                painter.drawText(QRectF(inset, y, 78 - inset, 24), Qt.AlignmentFlag.AlignVCenter, name.upper() if name in {"sca", "yara", "owasp", "zap", "ai"} else name.title())
                self.draw_bar(painter, QRectF(82, y + 5, max(2, durations[index] / maximum * (self.width() - 148)), 12),
                              QColor(colors["chart-2"] if name == "zap" else colors["chart-1"]))
                painter.setPen(QColor(colors["text-secondary"]))
                value_width = 52 if get_skin().hardware or get_skin().monochrome else 58
                painter.drawText(QRectF(self.width() - 60, y, value_width, 24), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, f"{durations[index]:.1f}s")
        painter.end()
