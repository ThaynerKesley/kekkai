"""Additional desktop launcher. The original secscan.py CLI is preserved."""
from secscan.gui.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
