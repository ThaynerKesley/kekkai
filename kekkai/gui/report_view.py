"""Offline report viewer with no persistent browser profile or remote access."""
from ..i18n import tr
from pathlib import Path
import json
from PySide6.QtCore import QUrl, QTemporaryDir, QDir, QObject, Signal, QTimer, QMarginsF
from PySide6.QtGui import QPageLayout, QPageSize
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings, QWebEngineUrlRequestInterceptor
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QVBoxLayout, QHBoxLayout, QWidget

from ..dashboard import render, appearance
from ..skins import get_skin
from ..files import atomic_write_bytes
from .widgets import button


class OfflineInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.allowed_file = ""

    def interceptRequest(self, info):
        url = info.requestUrl()
        allowed = url.scheme() in {"data", "about", "qrc"} or (url.scheme() == "file" and Path(url.toLocalFile()) == Path(self.allowed_file))
        if not allowed:
            info.block(True)


class OfflinePage(QWebEnginePage):
    allowed_file = ""

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
        return url.scheme() in {"about", "data"} or (url.scheme() == "file" and Path(url.toLocalFile()) == Path(self.allowed_file))


class DashboardPage(QWidget):
    def __init__(self, parent=None, *, controls=True):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        if controls:
            actions = QHBoxLayout()
            actions.setContentsMargins(24, 12, 24, 0)
            actions.addStretch()
            for text, action in [(tr("Abrir no navegador"), "browser"), (tr("Exportar HTML"), "html"), (tr("Exportar PDF"), "pdf")]:
                actions.addWidget(button(text, lambda checked=False, kind=action: parent.export_dashboard(kind, self.summary), name="dashboard_" + action))
            layout.addLayout(actions)
        self.view = QWebEngineView(self)
        self.profile = QWebEngineProfile(self.view)  # No storage name: off-the-record profile.
        self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
        self.interceptor = OfflineInterceptor(self.profile)
        self.profile.setUrlRequestInterceptor(self.interceptor)
        self.page = OfflinePage(self.profile, self.view)
        self.view.setPage(self.page)
        settings = self.view.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, False)
        layout.addWidget(self.view)
        self.summary = None
        self.theme = "dark"
        self.skin = get_skin().identifier
        self.view.loadFinished.connect(lambda success: self.apply_appearance() if success else None)
        self.temporary = QTemporaryDir(str(Path(QDir.tempPath()) / "kekkai-report-XXXXXX"))
        if not self.temporary.isValid():
            raise OSError(tr("Não foi possível preparar o renderer de relatórios."))

    def show_summary(self, summary, theme, *, language=None):
        self.summary = summary
        self.theme = theme
        self.skin = get_skin().identifier
        # setHtml has a ~2 MB Chromium URL limit; an offline sanitized HTML file scales to real reports.
        path = Path(self.temporary.path()).resolve() / "report.html"
        path.write_text(render(summary, theme, embedded=True, language=language, skin=self.skin), encoding="utf-8")
        self.interceptor.allowed_file = str(path)
        self.page.allowed_file = str(path)
        self.view.setUrl(QUrl.fromLocalFile(str(path)))

    def set_theme(self, theme):
        self.theme = theme
        self.skin = get_skin().identifier
        if theme in {"light", "dark"}:
            self.apply_appearance()

    def apply_appearance(self):
        # Update presentation in place so report filters and the scroll position survive.
        if self.summary is None:
            return
        visual = appearance(self.skin)
        visual["theme"] = self.theme
        data = json.dumps(visual).replace("<", "\\u003c")
        self.page.runJavaScript("""((visual) => {
            const style = document.querySelector('head style');
            if (!style || !window.kekkaiSetTheme) return;
            style.textContent = visual.css;
            document.documentElement.dataset.skin = visual.skin;
            const brand = document.querySelector('.brand-image');
            if (brand) brand.src = visual.wordmark;
            const favicon = document.querySelector('link[rel="icon"]');
            if (favicon) favicon.href = visual.icon;
            window.kekkaiSetTheme(visual.theme);
        })(""" + data + ");")

    def cleanup(self):
        self.view.stop()
        self.view.setUrl(QUrl("about:blank"))
        self.temporary.remove()

    def clear(self):
        self.view.stop()
        self.view.setUrl(QUrl('about:blank'))
        self.view.history().clear()
        self.summary=None
        path=Path(self.temporary.path())/'report.html'
        if path.exists():path.unlink()


class PdfExport(QObject):
    """Render an isolated complete snapshot, without changing the visible dashboard."""
    finished = Signal(str, bool)

    def __init__(self, parent):
        super().__init__(parent)
        self.renderer = DashboardPage(parent, controls=False)
        self.renderer.hide()
        self.renderer.view.loadFinished.connect(self.loaded)
        self.renderer.page.renderProcessTerminated.connect(lambda *_: self.finish(False))
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(lambda: self.finish(False))
        self.done = False
        self.destination = None

    def start(self, summary, destination: Path, language: str):
        self.destination = destination
        self.timer.start(60000)
        self.renderer.show_summary(summary, "light", language=language)

    def loaded(self, success):
        if self.done:
            return
        if not success:
            self.finish(False)
            return
        self.renderer.page.runJavaScript(
            "Boolean(window.kekkaiPreparePrint && window.kekkaiPreparePrint())", self.prepared
        )

    def prepared(self, ready):
        if self.done:
            return
        if not ready:
            self.finish(False)
            return
        layout = QPageLayout(QPageSize(QPageSize.PageSizeId.A4), QPageLayout.Orientation.Portrait,
                             QMarginsF(12, 12, 12, 12), QPageLayout.Unit.Millimeter)
        self.renderer.page.printToPdf(self.printed, layout)

    def printed(self, data):
        # Qt can invoke this callback with invalid data while destroying a page.
        if self.done:
            return
        contents = bytes(data) if data else b""
        success = contents.startswith(b"%PDF-")
        if success:
            try:
                atomic_write_bytes(self.destination, contents)
            except OSError:
                success = False
        self.finish(success)

    def finish(self, success):
        if self.done:
            return
        self.done = True
        self.timer.stop()
        self.renderer.cleanup()
        self.renderer.deleteLater()
        self.finished.emit(str(self.destination), success)
        self.deleteLater()
