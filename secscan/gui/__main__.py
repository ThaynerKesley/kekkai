"""Run with python -m secscan.gui [project directory]."""
from ..i18n import tr
import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Kekkai Desktop")
    parser.add_argument("target", nargs="?")
    parser.add_argument("--language", choices=["pt_BR", "en"], help="Interface language / idioma da interface")
    args = parser.parse_args()
    from ..secscan import configure_stdio
    configure_stdio()
    try:
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import QApplication, QMessageBox
        from .window import MainWindow
    except ImportError:
        print(tr("GUI requer PySide6. Execute python -m pip install -r requirements-gui.txt."))
        return 1
    app = QApplication(sys.argv[:1])
    app.setApplicationName("Kekkai Desktop")
    app.setOrganizationName("Kekkai")
    app.setFont(QFont("Segoe UI", 10))
    try:
        window = MainWindow(target=Path(args.target).resolve() if args.target else None, language=args.language)
    except (OSError, ValueError):
        QMessageBox.critical(None, "Kekkai", tr("Não foi possível abrir o workspace. Verifique o projeto e as preferências locais."))
        return 1
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
