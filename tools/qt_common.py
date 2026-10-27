from __future__ import annotations

from pathlib import Path

from tool_log import tagged

QT_DIR = Path("third_party") / "qt"
STAMP_NAME = "cerf_qt.json"

say = tagged("QT")
