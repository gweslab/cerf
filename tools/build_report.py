from __future__ import annotations

from datetime import datetime
from pathlib import Path


def build_exit_failed(name: str, code: int) -> None:
    print("[BUILD] {} FAILED (cmake --build exit={})".format(name, code), flush=True)


def built_file_present(name: str, path: Path, what: str) -> bool:
    if path.is_file():
        return True
    print("[BUILD] {} FAILED (the build reported success but the {} is not at {})".format(name, what, path),
          flush=True)
    return False


def built_file(name: str, path: Path) -> None:
    stat = path.stat()
    print("[BUILD] {} OK: {}".format(name, path), flush=True)
    print("[BUILD] Size: {} bytes".format(stat.st_size), flush=True)
    print("[BUILD] Time: {}".format(datetime.fromtimestamp(stat.st_mtime)), flush=True)


def deploy_failed(error: Exception) -> None:
    print("[DEPLOY] FAILED! {}".format(error), flush=True)
