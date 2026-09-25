from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable, Optional

from app_paths import resolve_asset, resolve_icons_dir
from dialog_buttons import ACCENT_STYLE
import ui_theme as theme


BAND_DIP_W = 400
BAND_SCALES = (100, 125, 150, 200, 300)
ICON_SIZES = (32, 40, 48, 64, 96)
ICON_DIP = 32

SETUP_ICON_STEM = "cerf_setup"
UNINSTALL_ICON_STEM = "cerf_error"

PAD_DIP = 16
GAP_DIP = 12


def ui_scale(widget: tk.Misc) -> float:
    try:
        return max(1.0, float(widget.winfo_fpixels("1i")) / 96.0)
    except tk.TclError:
        return 1.0


def scaled(widget: tk.Misc, dip: int) -> int:
    return int(round(dip * ui_scale(widget)))


def _band_file(scale: float) -> Optional[Path]:
    pct = int(round(scale * 100))
    tier = BAND_SCALES[-1]
    for candidate in BAND_SCALES[:-1]:
        if pct <= candidate:
            tier = candidate
            break
    return resolve_asset("about_band_{}.png".format(tier))


def load_band(widget: tk.Misc) -> Optional[tk.PhotoImage]:
    path = _band_file(ui_scale(widget))
    if path is None:
        return None
    try:
        return tk.PhotoImage(master=widget, file=str(path))
    except tk.TclError:
        return None


def load_dialog_icon(widget: tk.Misc, stem: str) -> Optional[tk.PhotoImage]:
    icons = resolve_icons_dir()
    if icons is None:
        return None
    want = ICON_DIP * ui_scale(widget)
    px = next((s for s in ICON_SIZES if s >= want), ICON_SIZES[-1])
    try:
        return tk.PhotoImage(master=widget,
                             file=str(icons / "{}_{}.png".format(stem, px)))
    except tk.TclError:
        return None


def _own_image(widget: tk.Widget, image: tk.PhotoImage) -> None:
    widget.image = image


class BrandedDialog:

    def __init__(self, window: tk.Misc, title: str,
                 heading: Optional[str] = None,
                 icon_stem: Optional[str] = None) -> None:
        self.window = window
        window.title(title)
        window.configure(bg=theme.BG)
        try:
            window.resizable(False, False)
        except tk.TclError:
            pass

        self._band = load_band(window)
        self._icon = (load_dialog_icon(window, icon_stem)
                      if icon_stem is not None else None)

        if self._band is not None:
            band = tk.Label(window, image=self._band, bg=theme.BG,
                            borderwidth=0, highlightthickness=0)
            _own_image(band, self._band)
            band.pack(side="top", fill="x")
            self.width = self._band.width()
        else:
            self.width = scaled(window, BAND_DIP_W)

        pad = scaled(window, PAD_DIP)
        gap = scaled(window, GAP_DIP)

        outer = ttk.Frame(window, padding=pad)
        outer.pack(side="top", fill="both", expand=True)

        self.head = head = ttk.Frame(outer)
        head.pack(side="top", fill="x")
        self.body_width = self.width - 2 * pad
        self.text_width = self.body_width
        if self._icon is not None:
            icon = tk.Label(head, image=self._icon, bg=theme.BG, borderwidth=0,
                            highlightthickness=0)
            _own_image(icon, self._icon)
            icon.pack(side="left", padx=(0, gap))
            self.text_width -= self._icon.width() + gap
        self.heading = None
        if heading is not None:
            self.heading = ttk.Label(head, text=heading, anchor="w",
                                     wraplength=self.text_width,
                                     justify="left")
            self.heading.pack(side="left", anchor="w", fill="x", expand=True)

        self.buttons = ttk.Frame(outer)
        self.buttons.pack(side="bottom", fill="x", pady=(gap, 0))

        self.body = ttk.Frame(outer)
        self.body.pack(side="top", fill="both", expand=True, pady=(gap, 0))

    def set_heading(self, text: str) -> None:
        self.heading.configure(text=text)

    def add_button(self, label: str, command: Callable[[], None],
                   style: Optional[str] = None,
                   default: bool = False) -> ttk.Button:
        if style is None:
            style = ACCENT_STYLE if default else "TButton"
        btn = ttk.Button(self.buttons, text=label, command=command, style=style)
        btn.pack(side="right", padx=(scaled(self.window, 6), 0))
        if default:
            btn.focus_set()
            self.window.bind("<Return>", lambda _e: command())
        return btn

    def add_left_button(self, label: str,
                        command: Callable[[], None]) -> ttk.Button:
        btn = ttk.Button(self.buttons, text=label, command=command)
        btn.pack(side="left")
        return btn

    def refit(self) -> None:
        self.window.update_idletasks()
        self.window.geometry("{}x{}".format(self.width,
                                            self.window.winfo_reqheight()))

    def present(self, parent: Optional[tk.Misc] = None) -> None:
        self.window.update_idletasks()
        width = self.width
        height = self.window.winfo_reqheight()
        if parent is not None and parent.winfo_width() > 1:
            x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - height) // 2
        else:
            x = (self.window.winfo_screenwidth() - width) // 2
            y = (self.window.winfo_screenheight() - height) // 2
        self.window.geometry("{}x{}+{}+{}".format(width, height,
                                                  max(0, x), max(0, y)))
        theme.apply_titlebar(self.window)
