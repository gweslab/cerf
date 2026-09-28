from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import List, Optional

from app_paths import resolve_icon
from crash_window import CrashWindow
from text_context_menu import TextContextMenu
import ui_theme as theme


TRANSACTIONAL_CRASH_COMMAND = "transactional-crash"


def run_transactional_crash(argv: List[str]) -> int:
    log_path: Optional[Path] = None
    if argv and argv[0].strip():
        log_path = Path(argv[0])

    root = tk.Tk()
    theme.apply_theme(root)
    TextContextMenu(root)
    root.withdraw()
    icon = resolve_icon()
    if icon is not None:
        try:
            root.iconbitmap(default=str(icon))
        except tk.TclError:
            pass

    CrashWindow(root, log_path)
    root.deiconify()
    root.lift()
    root.focus_force()
    root.mainloop()
    return 0
