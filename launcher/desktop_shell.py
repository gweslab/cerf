from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from child_process import spawn_detached


def open_path(path: Path) -> None:
    target = Path(os.path.abspath(str(path)))
    if sys.platform == "win32":
        os.startfile(str(target))
    elif sys.platform == "darwin":
        spawn_detached(["open", str(target)], target.parent)
    else:
        spawn_detached(["xdg-open", str(target)], target.parent)


def show_item(path: Path) -> None:
    if sys.platform == "win32":
        subprocess.Popen('explorer /select,"{}"'.format(path))
    elif sys.platform == "darwin":
        spawn_detached(["open", "-R", str(path)], path.parent)
    else:
        from freedesktop_services import show_item as show_in_file_manager
        show_in_file_manager(path)
