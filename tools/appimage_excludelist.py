from __future__ import annotations

from pathlib import Path

from qt_common import say
from verified_download import fetch_verified

COMMIT = "15a64c20dc23a0154622ba25829364323903b6b5"
URL = "https://raw.githubusercontent.com/AppImageCommunity/pkg2appimage/{}/excludelist".format(COMMIT)
SHA256 = "50db0f894f34b169c47a5cbc0c17dbab61e9edebca5bc8269a1e6ac1bf4bdad9"


def ensure(root: Path) -> Path:
    return fetch_verified(URL, root / "third_party" / "appimage" / "excludelist-{}".format(COMMIT[:12]), SHA256, say)
