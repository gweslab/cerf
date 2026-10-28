from __future__ import annotations

import sys
import zipfile
from pathlib import Path

from tool_log import tagged
from verified_download import DownloadError, fetch_verified

CCACHE_VERSION = "4.12.3"
ARCHIVE = "ccache-{}-windows-x86_64".format(CCACHE_VERSION)
ARCHIVE_URL = "https://github.com/ccache/ccache/releases/download/v{}/{}.zip".format(CCACHE_VERSION, ARCHIVE)
ARCHIVE_SHA256 = "859141059ac950e1e8cd042c66f842f26b9e3a62a1669a69fe6ba180cb58bbdf"
CCACHE_DIR = Path("third_party") / "ccache"

say = tagged("CCACHE")


def install(root: Path) -> Path:
    folder = root / CCACHE_DIR / CCACHE_VERSION
    exe_dir = folder / ARCHIVE
    if (exe_dir / "ccache.exe").is_file():
        return exe_dir
    archive = fetch_verified(ARCHIVE_URL, root / CCACHE_DIR / "downloads" / (ARCHIVE + ".zip"), ARCHIVE_SHA256, say)
    with zipfile.ZipFile(str(archive)) as unpacked:
        unpacked.extractall(str(folder))
    return exe_dir


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--install":
        raise SystemExit("usage: ccache_windows.py --install <path file>")
    try:
        exe_dir = install(Path(__file__).resolve().parent.parent)
    except (DownloadError, OSError) as exc:
        say("FAILED! {}".format(exc))
        raise SystemExit(1)
    with open(sys.argv[2], "a", encoding="utf-8") as path_file:
        path_file.write(str(exe_dir) + "\n")
