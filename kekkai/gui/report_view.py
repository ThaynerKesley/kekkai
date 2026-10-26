"""Offline report viewer with no persistent browser profile or remote access."""
from ..i18n import tr
from pathlib import Path
from PySide6.QtCore import QUrl, QTemporaryDir, QDir
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings, QWebEngineUrlRequestInterceptor
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QVBoxLayout, QWidget

from ..dashboard import render


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
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
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
        self.temporary = QTemporaryDir(str(Path(QDir.tempPath()) / "kekkai-report-XXXXXX"))
        if not self.temporary.isValid():
            raise OSError(tr("Não foi possível preparar o renderer de relatórios."))

    def show_summary(self, summary, theme):
        self.summary = summary
        self.theme = theme
        # setHtml has a ~2 MB Chromium URL limit; an offline sanitized HTML file scales to real reports.
        path = Path(self.temporary.path()).resolve() / "report.html"
        path.write_text(render(summary, theme, embedded=True), encoding="utf-8")
        self.interceptor.allowed_file = str(path)
        self.page.allowed_file = str(path)
        self.view.setUrl(QUrl.fromLocalFile(str(path)))

    def set_theme(self, theme):
        self.theme = theme
        if theme in {"light", "dark"}:
            self.page.runJavaScript(f'if (window.kekkaiSetTheme) window.kekkaiSetTheme("{theme}");')

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
