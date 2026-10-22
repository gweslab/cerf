from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import List, Optional

from window_icon import apply_window_icon
from crash_window import CrashWindow
from macos_menubar import install_macos_menubar
from text_context_menu import TextContextMenu
import ui_theme as theme


TRANSACTIONAL_CRASH_COMMAND = "transactional-crash"


def run_transactional_crash(argv: List[str]) -> int:
    log_path: Optional[Path] = None
    if argv and argv[0].strip():
        log_path = Path(argv[0])

    root = tk.Tk()
    install_macos_menubar(root)
    theme.apply_theme(root)
    TextContextMenu(root)
    root.withdraw()
    apply_window_icon(root)

    CrashWindow(root, log_path)
    root.deiconify()
    root.lift()
    root.focus_force()
    root.mainloop()
    return 0
