from __future__ import annotations

import sys
import tkinter as tk
from typing import Callable, Optional

from branding import LAUNCHER_PRODUCT_NAME


def install_macos_menubar(root: tk.Tk, on_about: Optional[Callable[[], None]] = None,
                          on_preferences: Optional[Callable[[], None]] = None) -> None:
    if sys.platform != "darwin":
        return
    menubar = tk.Menu(root, name="cerfmenubar", tearoff=0)
    application = tk.Menu(menubar, name="apple", tearoff=0)
    if on_about is not None:
        application.add_command(label="About " + LAUNCHER_PRODUCT_NAME, command=on_about)
    menubar.add_cascade(menu=application)
    menubar.add_cascade(label="Window", menu=tk.Menu(menubar, name="window", tearoff=0))
    if on_preferences is not None:
        root.createcommand("::tk::mac::ShowPreferences", on_preferences)
    root.configure(menu=menubar)
    root.option_add("*Toplevel.menu", str(menubar))
