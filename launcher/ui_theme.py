"""Theme: a light/dark palette chosen from the Windows app theme, ttk style
setup, DPI awareness, and the Win32 immersive titlebar attribute."""
from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Dict, Optional

import sv_ttk

import sv_elements
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
    "BG": "#1c1c1c", "BG_LIGHTER": "#252526", "BG_FIELD": "#2d2d30",
    "BG_HOVER": "#3c3c3c", "BG_SELECTED": "#094771", "FG": "#fafafa",
    "FG_DIM": "#808080", "BORDER": "#3f3f46", "SEPARATOR": "#343434",
    "UPDATE_LINK": "#e8c44a",
    "LINK_FG": "#569cd6", "GROUP_BG": "#252526", "PREVIEW_STOPPED": "#cfcfcf",
    "DANGER_FG": "#f48771", "WARN_FG": "#ffb900",
    "CARD_RUNNING_BG": "#1e3a1e", "CARD_UPDATE_BG": "#3a2f12",
    "CARD_RUNNING_SEL": "#2e5a2e", "CARD_UPDATE_SEL": "#5c4a1e",
}
_LIGHT_PALETTE: Dict[str, str] = {
    "BG": "#fafafa", "BG_LIGHTER": "#ffffff", "BG_FIELD": "#ffffff",
    "BG_HOVER": "#e6e6e6", "BG_SELECTED": "#cce4f7", "FG": "#1c1c1c",
    "FG_DIM": "#6b6b6b", "BORDER": "#c4c4c4", "SEPARATOR": "#dbdbdb",
    "UPDATE_LINK": "#8a5a00",
    "LINK_FG": "#0a66c2", "GROUP_BG": "#ececec", "PREVIEW_STOPPED": "#8a8a8a",
    "DANGER_FG": "#c42b1c", "WARN_FG": "#8a5a00",
    "CARD_RUNNING_BG": "#dff3df", "CARD_UPDATE_BG": "#fbeecb",
    "CARD_RUNNING_SEL": "#bfe6bf", "CARD_UPDATE_SEL": "#f2dca0",
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
CARD_RUNNING_BG = _PALETTE["CARD_RUNNING_BG"]
CARD_UPDATE_BG  = _PALETTE["CARD_UPDATE_BG"]
CARD_RUNNING_SEL = _PALETTE["CARD_RUNNING_SEL"]
CARD_UPDATE_SEL  = _PALETTE["CARD_UPDATE_SEL"]


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
    global CARD_RUNNING_BG, CARD_UPDATE_BG, CARD_RUNNING_SEL, CARD_UPDATE_SEL
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
    CARD_RUNNING_BG = _PALETTE["CARD_RUNNING_BG"]
    CARD_UPDATE_BG  = _PALETTE["CARD_UPDATE_BG"]
    CARD_RUNNING_SEL = _PALETTE["CARD_RUNNING_SEL"]
    CARD_UPDATE_SEL  = _PALETTE["CARD_UPDATE_SEL"]
    STATE_TINT = _build_state_tint()
    return True


def blend(color: str, target: str, t: float) -> str:
    def channel(i: int) -> int:
        a = int(color[i:i + 2], 16)
        b = int(target[i:i + 2], 16)
        return max(0, min(255, int(round(a + (b - a) * t))))
    return "#{:02x}{:02x}{:02x}".format(channel(1), channel(3), channel(5))


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


def _use_sun_valley(root: tk.Tk) -> None:
    if "sun-valley-dark" not in root.tk.call("ttk::style", "theme", "names"):
        root.tk.call("source", str(Path(sv_ttk.__file__).parent / "sv.tcl"))
    root.tk.call("set_theme", "dark" if IS_DARK else "light")


def apply_theme(root: tk.Tk) -> None:
    _use_sun_valley(root)
    style = ttk.Style(root)
    sv_elements.create(root, style)

    style.configure("Toolbar.TButton", padding=(3, 1))

    style.configure("Danger.TButton", foreground=DANGER_FG)
    style.map("Danger.TButton", foreground=[("disabled", FG_DIM)])


    style.configure("Hint.TLabel", foreground=FG_DIM)
    style.configure("Danger.TLabel", foreground=DANGER_FG)

    style.configure("Help.TButton", padding=(4, 1))

    root.option_add("*TCombobox*Listbox.background", BG_FIELD)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.selectBackground", BG_SELECTED)
    root.option_add("*TCombobox*Listbox.selectForeground", FG)
