#!/usr/bin/env python3
from __future__ import annotations

import sys
import tkinter as tk
import traceback
from pathlib import Path
from typing import List

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from app_paths import resolve_icon
from installer_window import SETUP_ICO_NAME, InstallerWindow
from text_context_menu import TextContextMenu
from ui_theme import apply_theme, enable_dpi_awareness


def main(argv: List[str]) -> int:
    del argv
    enable_dpi_awareness()

    root = tk.Tk()
    root.withdraw()
    apply_theme(root)
    TextContextMenu(root)
    icon = resolve_icon(SETUP_ICO_NAME)
    if icon is not None:
        try:
            root.iconbitmap(default=str(icon))
        except tk.TclError:
            pass

    try:
        InstallerWindow(root)
        root.mainloop()
    except Exception:
        traceback.print_exc()
        return 1
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
