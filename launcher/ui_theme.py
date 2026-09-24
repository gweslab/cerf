"""Theme: a light/dark palette chosen from the Windows app theme, ttk style
setup, DPI awareness, and the Win32 immersive titlebar attribute."""
from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Dict, Optional

from device_state import (
    STATE_AVAILABLE,
    STATE_INSTALLED,
    STATE_UPDATE,
    STATE_USER,
)


def system_uses_dark() -> bool:
    """HKCU Personalize AppsUseLightTheme: 1 = light, 0 = dark; absent or
    unreadable -> light."""
    if sys.platform != "win32":
        return False
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return int(value) == 0
    except (OSError, ValueError):
        return False


_DARK_PALETTE: Dict[str, str] = {
    "BG": "#1e1e1e", "BG_LIGHTER": "#252526", "BG_FIELD": "#2d2d30",
    "BG_HOVER": "#3c3c3c", "BG_SELECTED": "#094771", "FG": "#e0e0e0",
    "FG_DIM": "#808080", "BORDER": "#3f3f46", "SEPARATOR": "#343434",
    "UPDATE_LINK": "#e8c44a",
    "LINK_FG": "#569cd6", "GROUP_BG": "#252526", "PREVIEW_STOPPED": "#cfcfcf",
    "DANGER_FG": "#f48771", "WARN_FG": "#ffb900", "LAUNCH_FG": "#3fb950",
    "CARD_RUNNING_BG": "#1e3a1e", "CARD_UPDATE_BG": "#3a2f12",
    "CARD_RUNNING_SEL": "#2e5a2e", "CARD_UPDATE_SEL": "#5c4a1e",
    "DANGER_BG_HOVER": "#3a1e1e", "DANGER_BG_PRESSED": "#5a1d1d",
    "DANGER_FG_PRESSED": "#f48771",
}
_LIGHT_PALETTE: Dict[str, str] = {
    "BG": "#f3f3f3", "BG_LIGHTER": "#ffffff", "BG_FIELD": "#ffffff",
    "BG_HOVER": "#e6e6e6", "BG_SELECTED": "#cce4f7", "FG": "#1b1b1b",
    "FG_DIM": "#6b6b6b", "BORDER": "#c4c4c4", "SEPARATOR": "#dbdbdb",
    "UPDATE_LINK": "#8a5a00",
    "LINK_FG": "#0a66c2", "GROUP_BG": "#ececec", "PREVIEW_STOPPED": "#8a8a8a",
    "DANGER_FG": "#c42b1c", "WARN_FG": "#8a5a00", "LAUNCH_FG": "#107c10",
    "CARD_RUNNING_BG": "#dff3df", "CARD_UPDATE_BG": "#fbeecb",
    "CARD_RUNNING_SEL": "#bfe6bf", "CARD_UPDATE_SEL": "#f2dca0",
    "DANGER_BG_HOVER": "#fbe4e1", "DANGER_BG_PRESSED": "#f4cbc5",
    "DANGER_FG_PRESSED": "#a1260d",
}

IS_DARK = system_uses_dark()
_PALETTE = _DARK_PALETTE if IS_DARK else _LIGHT_PALETTE

BG          = _PALETTE["BG"]
BG_LIGHTER  = _PALETTE["BG_LIGHTER"]
BG_FIELD    = _PALETTE["BG_FIELD"]
BG_HOVER    = _PALETTE["BG_HOVER"]
BG_SELECTED = _PALETTE["BG_SELECTED"]
FG          = _PALETTE["FG"]
FG_DIM      = _PALETTE["FG_DIM"]
BORDER      = _PALETTE["BORDER"]
SEPARATOR   = _PALETTE["SEPARATOR"]
UPDATE_LINK = _PALETTE["UPDATE_LINK"]
LINK_FG     = _PALETTE["LINK_FG"]
GROUP_BG    = _PALETTE["GROUP_BG"]
PREVIEW_STOPPED = _PALETTE["PREVIEW_STOPPED"]
DANGER_FG   = _PALETTE["DANGER_FG"]
WARN_FG     = _PALETTE["WARN_FG"]
LAUNCH_FG   = _PALETTE["LAUNCH_FG"]
CARD_RUNNING_BG = _PALETTE["CARD_RUNNING_BG"]
CARD_UPDATE_BG  = _PALETTE["CARD_UPDATE_BG"]
CARD_RUNNING_SEL = _PALETTE["CARD_RUNNING_SEL"]
CARD_UPDATE_SEL  = _PALETTE["CARD_UPDATE_SEL"]
DANGER_BG_HOVER   = _PALETTE["DANGER_BG_HOVER"]
DANGER_BG_PRESSED = _PALETTE["DANGER_BG_PRESSED"]
DANGER_FG_PRESSED = _PALETTE["DANGER_FG_PRESSED"]


def _build_state_tint() -> dict:
    return {
        STATE_INSTALLED: "#1e3a1e" if IS_DARK else "#e3f3e3",
        STATE_UPDATE:    "#3a2f12" if IS_DARK else "#fbf0d8",
        STATE_AVAILABLE: BG_FIELD,
        STATE_USER:      "#3a1e3a" if IS_DARK else "#f3e3f3",
    }


STATE_TINT = _build_state_tint()


def refresh_palette() -> bool:
    """Re-read the OS theme; if it changed since last time, swap the live
    palette (every module reads colours as ui_theme.<NAME>) and return True so
    the caller re-runs apply_theme + per-widget retheme(). No change -> False."""
    global IS_DARK, _PALETTE, STATE_TINT
    global BG, BG_LIGHTER, BG_FIELD, BG_HOVER, BG_SELECTED, FG, FG_DIM, BORDER
    global SEPARATOR
    global UPDATE_LINK, LINK_FG, GROUP_BG, PREVIEW_STOPPED, DANGER_FG, WARN_FG
    global LAUNCH_FG
    global CARD_RUNNING_BG, CARD_UPDATE_BG, CARD_RUNNING_SEL, CARD_UPDATE_SEL
    global DANGER_BG_HOVER, DANGER_BG_PRESSED, DANGER_FG_PRESSED
    dark = system_uses_dark()
    if dark == IS_DARK:
        return False
    IS_DARK = dark
    _PALETTE = _DARK_PALETTE if dark else _LIGHT_PALETTE
    BG          = _PALETTE["BG"]
    BG_LIGHTER  = _PALETTE["BG_LIGHTER"]
    BG_FIELD    = _PALETTE["BG_FIELD"]
    BG_HOVER    = _PALETTE["BG_HOVER"]
    BG_SELECTED = _PALETTE["BG_SELECTED"]
    FG          = _PALETTE["FG"]
    FG_DIM      = _PALETTE["FG_DIM"]
    BORDER      = _PALETTE["BORDER"]
    SEPARATOR   = _PALETTE["SEPARATOR"]
    UPDATE_LINK = _PALETTE["UPDATE_LINK"]
    LINK_FG     = _PALETTE["LINK_FG"]
    GROUP_BG    = _PALETTE["GROUP_BG"]
    PREVIEW_STOPPED = _PALETTE["PREVIEW_STOPPED"]
    DANGER_FG   = _PALETTE["DANGER_FG"]
    WARN_FG     = _PALETTE["WARN_FG"]
    LAUNCH_FG   = _PALETTE["LAUNCH_FG"]
    CARD_RUNNING_BG = _PALETTE["CARD_RUNNING_BG"]
    CARD_UPDATE_BG  = _PALETTE["CARD_UPDATE_BG"]
    CARD_RUNNING_SEL = _PALETTE["CARD_RUNNING_SEL"]
    CARD_UPDATE_SEL  = _PALETTE["CARD_UPDATE_SEL"]
    DANGER_BG_HOVER   = _PALETTE["DANGER_BG_HOVER"]
    DANGER_BG_PRESSED = _PALETTE["DANGER_BG_PRESSED"]
    DANGER_FG_PRESSED = _PALETTE["DANGER_FG_PRESSED"]
    STATE_TINT = _build_state_tint()
    return True


def load_badge(icons_dir: Optional[Path], cpu: Optional[str],
               cache: Dict[str, Optional[tk.PhotoImage]]
               ) -> Optional[tk.PhotoImage]:
    """CPU-arch badge PNG (badge_<cpu>.png) at native size; cached in `cache`
    and kept referenced so Tk doesn't GC it. Returns None when unavailable."""
    if not cpu or icons_dir is None:
        return None
    key = cpu.lower()
    if key not in cache:
        try:
            cache[key] = tk.PhotoImage(file=str(icons_dir / f"badge_{key}.png"))
        except tk.TclError:
            cache[key] = None
    return cache[key]


def enable_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except (OSError, AttributeError):
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except (OSError, AttributeError):
        pass


GWLP_HWNDPARENT = -8


def window_hwnd(window: tk.Misc) -> int:
    window.update_idletasks()
    hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
    if hwnd == 0:
        hwnd = window.winfo_id()
    return hwnd


def set_window_long(hwnd: int, index: int, value):
    user32 = ctypes.windll.user32
    try:
        set_long = user32.SetWindowLongPtrW
    except AttributeError:
        set_long = user32.SetWindowLongW
    set_long.restype = ctypes.c_void_p
    set_long.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    return set_long(hwnd, index, value)


def set_owner_window(window: tk.Misc, owner_hwnd: int) -> None:
    if sys.platform != "win32" or not owner_hwnd:
        return
    try:
        hwnd = window_hwnd(window)
        if hwnd:
            set_window_long(hwnd, GWLP_HWNDPARENT,
                            ctypes.c_void_p(int(owner_hwnd)))
    except (OSError, AttributeError, ValueError):
        pass


def apply_titlebar(window: tk.Misc) -> None:
    if sys.platform != "win32":
        return
    try:
        hwnd = window_hwnd(window)
        value = ctypes.c_int(1 if IS_DARK else 0)
        if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(value), ctypes.sizeof(value)) != 0:
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 19, ctypes.byref(value), ctypes.sizeof(value))
    except (OSError, AttributeError):
        pass


def _apply_flat_separator(root: tk.Tk, style: ttk.Style) -> None:
    image = getattr(root, "_flat_separator_image", None)
    if image is None:
        image = tk.PhotoImage(master=root, width=1, height=1)
        root._flat_separator_image = image
        style.element_create("FlatSeparator.fill", "image", image,
                             sticky="nswe")
        for name in ("Horizontal.TSeparator", "Vertical.TSeparator"):
            style.layout(name, [("FlatSeparator.fill", {"sticky": "nswe"})])
    image.put(SEPARATOR, to=(0, 0, 1, 1))


def apply_theme(root: tk.Tk) -> None:
    root.configure(bg=BG)
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".",
                    background=BG, foreground=FG,
                    fieldbackground=BG_FIELD, bordercolor=BORDER,
                    lightcolor=BG, darkcolor=BG,
                    troughcolor=BG_FIELD,
                    selectbackground=BG_SELECTED, selectforeground=FG,
                    insertcolor=FG, focuscolor=BG_SELECTED)

    style.configure("TFrame",       background=BG)
    style.configure("TLabel",       background=BG, foreground=FG)
    style.configure("TSeparator",   background=SEPARATOR)
    _apply_flat_separator(root, style)
    style.configure("TLabelframe",  background=BG, foreground=FG,
                                   bordercolor=BORDER)
    style.configure("TLabelframe.Label", background=BG, foreground=FG)

    style.configure("TButton",
                    background=BG_FIELD, foreground=FG,
                    bordercolor=BORDER, padding=4, borderwidth=1)
    style.map("TButton",
              background=[("pressed", BG_SELECTED),
                          ("active",  BG_HOVER),
                          ("disabled", BG)],
              foreground=[("disabled", FG_DIM)],
              bordercolor=[("focus", BG_SELECTED)])

    style.configure("Accent.TButton",
                    background="#0e639c", foreground="#ffffff",
                    bordercolor="#0a4d7a", padding=4, borderwidth=1)
    style.map("Accent.TButton",
              background=[("pressed",  BG_SELECTED),
                          ("active",   "#1177bb"),
                          ("disabled", BG_FIELD)],
              foreground=[("disabled", FG_DIM)],
              bordercolor=[("focus", "#1177bb")])

    style.configure("Download.TButton",
                    background="#107c10", foreground="#ffffff",
                    bordercolor="#0b5a0b", padding=4, borderwidth=1)
    style.map("Download.TButton",
              background=[("pressed",  "#0b5a0b"),
                          ("active",   "#168a16"),
                          ("disabled", BG_FIELD)],
              foreground=[("disabled", FG_DIM)],
              bordercolor=[("focus", "#168a16")])

    style.configure("Danger.TButton",
                    background=BG_FIELD, foreground=DANGER_FG,
                    bordercolor="#a1260d", padding=4, borderwidth=1)
    style.map("Danger.TButton",
              background=[("pressed", DANGER_BG_PRESSED),
                          ("active",  DANGER_BG_HOVER),
                          ("disabled", BG)],
              foreground=[("pressed", DANGER_FG_PRESSED),
                          ("active", DANGER_FG),
                          ("disabled", FG_DIM)],
              bordercolor=[("disabled", BORDER),
                           ("focus", "#c42b1c")])

    style.configure("Launch.TButton",
                    background=BG_FIELD, foreground=LAUNCH_FG,
                    bordercolor=LAUNCH_FG, padding=4, borderwidth=1)
    style.map("Launch.TButton",
              background=[("pressed", CARD_RUNNING_SEL),
                          ("active",  CARD_RUNNING_BG),
                          ("disabled", BG)],
              foreground=[("disabled", FG_DIM)],
              bordercolor=[("disabled", BORDER),
                           ("focus", LAUNCH_FG)])

    for name, fg in (("Toolbar.TButton", FG),
                     ("ToolbarLaunch.TButton", LAUNCH_FG)):
        style.configure(name,
                        background=BG, foreground=fg,
                        bordercolor=BG, lightcolor=BG, darkcolor=BG,
                        focuscolor=BG, focusthickness=0, padding=(3, 1),
                        width=0, borderwidth=1)
        style.map(name,
                  background=[("pressed", BG_SELECTED),
                              ("active", BG_HOVER),
                              ("disabled", BG)],
                  bordercolor=[("pressed", BORDER), ("active", BORDER),
                               ("disabled", BG)],
                  lightcolor=[("pressed", BG_SELECTED), ("active", BG_HOVER),
                              ("disabled", BG)],
                  darkcolor=[("pressed", BG_SELECTED), ("active", BG_HOVER),
                             ("disabled", BG)],
                  foreground=[("disabled", FG_DIM)])

    style.configure("TCheckbutton",
                    background=BG, foreground=FG,
                    focuscolor=BG, indicatorcolor=BG_FIELD)
    style.map("TCheckbutton",
              background=[("active", BG)],
              foreground=[("disabled", FG_DIM)],
              indicatorcolor=[("selected", BG_SELECTED),
                              ("active",   BG_HOVER)])

    style.configure("TRadiobutton",
                    background=BG, foreground=FG,
                    focuscolor=BG, indicatorcolor=BG_FIELD)
    style.map("TRadiobutton",
              background=[("active", BG)],
              foreground=[("disabled", FG_DIM)],
              indicatorcolor=[("selected", BG_SELECTED),
                              ("active",   BG_HOVER)])

    style.configure("Guest.TCheckbutton",
                    background=BG, foreground=LINK_FG,
                    focuscolor=BG, indicatorcolor=BG_FIELD,
                    font=("Segoe UI", 10, "bold"))
    style.map("Guest.TCheckbutton",
              background=[("active", BG)],
              foreground=[("active", LINK_FG),
                          ("disabled", FG_DIM)],
              indicatorcolor=[("selected", "#107c10"),
                              ("active",   BG_HOVER)])

    style.configure("Hint.TLabel", background=BG, foreground=FG_DIM)
    style.configure("Danger.TLabel", background=BG, foreground=DANGER_FG)

    style.configure("Warn.TLabelframe", background=BG,
                    bordercolor="#9a6a00", lightcolor=BG, darkcolor=BG)
    style.configure("Warn.TLabelframe.Label", background=BG,
                    foreground=WARN_FG, font=("Segoe UI", 9, "bold"))

    style.configure("Help.TButton", padding=(4, 1))

    style.configure("TEntry",
                    fieldbackground=BG_FIELD, foreground=FG,
                    bordercolor=BORDER, insertcolor=FG)

    style.configure("TCombobox",
                    fieldbackground=BG_FIELD, background=BG_FIELD,
                    foreground=FG, arrowcolor=FG, bordercolor=BORDER,
                    lightcolor=BG_FIELD, darkcolor=BG_FIELD,
                    selectbackground=BG_SELECTED, selectforeground=FG,
                    padding=2)
    style.map("TCombobox",
              fieldbackground=[("readonly", BG_FIELD), ("disabled", BG)],
              foreground=[("disabled", FG_DIM)],
              background=[("active", BG_HOVER)],
              arrowcolor=[("disabled", FG_DIM)],
              bordercolor=[("focus", BG_SELECTED)],
              selectbackground=[("readonly", BG_FIELD)],
              selectforeground=[("readonly", FG)])
    # The readonly combobox's drop-down is a plain tk::listbox created lazily
    # by ttk::combobox; it reads its colours from the option database, not the
    # ttk style, so theme it via the documented *TCombobox*Listbox pattern.
    root.option_add("*TCombobox*Listbox.background", BG_FIELD)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.selectBackground", BG_SELECTED)
    root.option_add("*TCombobox*Listbox.selectForeground", FG)

    style.configure("TScrollbar",
                    background=BG_FIELD, troughcolor=BG,
                    bordercolor=BORDER, arrowcolor=FG)
    style.map("TScrollbar", background=[("active", BG_HOVER)])

    style.configure("Horizontal.TProgressbar",
                    background=BG_SELECTED, troughcolor=BG_FIELD,
                    bordercolor=BORDER, lightcolor=BG_SELECTED,
                    darkcolor=BG_SELECTED)

    style.configure("Res.Horizontal.TScale",
                    background=BG, troughcolor=BG_FIELD,
                    bordercolor=BORDER, lightcolor=BG_SELECTED,
                    darkcolor=BG_SELECTED)
    style.map("Res.Horizontal.TScale",
              background=[("active", BG_HOVER), ("disabled", BG)],
              troughcolor=[("disabled", BG)])

    style.configure("Treeview",
                    background=BG_FIELD, foreground=FG,
                    fieldbackground=BG_FIELD, bordercolor=BORDER,
                    rowheight=24)
    style.map("Treeview",
              background=[("selected", BG_SELECTED)],
              foreground=[("selected", FG)])
    style.configure("Treeview.Heading",
                    background=BG_LIGHTER, foreground=FG,
                    bordercolor=BORDER, relief="flat")
    style.map("Treeview.Heading",
              background=[("active", BG_HOVER)])
