"""Keep runtime and personal files outside the source distribution."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(shutil.which("git"), "Git is required to verify publication rules")
class DistributionTests(unittest.TestCase):
    def test_only_reviewed_source_paths_are_publishable(self):
        source = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(prefix="kekkai-distribution-") as folder:
            root = Path(folder)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            shutil.copyfile(source / ".gitignore", root / ".gitignore")
            for relative in ("kekkai/assets", "kekkai/gui", "tests"):
                (root / relative).mkdir(parents=True, exist_ok=True)
            private = [
                ".kekkai.yml", ".security/reports/summary.json", "personal-notes.md",
                "local-script.py", ".env", "private.key", "report.zip",
                "kekkai/assets/screenshot.png", "kekkai/gui/.env",
                "kekkai/gui/credentials.json", "kekkai/gui/__pycache__/window.pyc",
                "tests/personal-notes.md",
                "kekkai/skins/retro/.env", "kekkai/skins/violet/screenshot.png",
                "kekkai/skins/hardware/.env", "kekkai/skins/hardware/screenshot.png",
                "kekkai/skins/monochrome-crt/.env", "kekkai/skins/monochrome-crt/screenshot.png",
                "kekkai/staging.py", "tests/test_staging.py", "start-staging.pyw",
                "kekkai-stage/kekkai/engine.py", ".stage-data/desktop/preferences.json",
            ]
            publishable = [
                "README.md", "LICENSE", "requirements.txt", ".kekkai.example.yml",
                "kekkai.py", "kekkai/engine.py", "kekkai/gui/window.py",
                "kekkai/assets/logo.png", "kekkai/assets/logo+nome.png",
                "tests/test_distribution.py",
                "kekkai/skins/__init__.py", "kekkai/skins/retro/tokens.json",
                "kekkai/skins/retro/desktop.qss", "kekkai/skins/violet/tokens.json",
                "kekkai/skins/violet/desktop.qss", "kekkai/assets/Logo Kekkai retro.png",
                "kekkai/skins/hardware/tokens.json", "kekkai/skins/hardware/desktop.qss",
                "kekkai/assets/logo-hardware.png",
                "kekkai/skins/monochrome-crt/tokens.json", "kekkai/skins/monochrome-crt/desktop.qss",
                "kekkai/assets/logo-monochrome-crt.png",
            ]
            for relative in private + publishable:
                with self.subTest(path=relative):
                    result = subprocess.run(
                        ["git", "check-ignore", "--quiet", "--no-index", relative],
                        cwd=root, capture_output=True, check=False,
                    )
                    self.assertIn(result.returncode, (0, 1))
                    self.assertEqual(result.returncode == 0, relative in private)


if __name__ == "__main__":
    unittest.main()
