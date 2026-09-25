from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter import font as tkfont
from tkinter import ttk
from typing import List

from app_paths import resolve_asset, resolve_version_parts
from branded_dialog import BrandedDialog, scaled
from branding import AUTHOR, AUTHOR_URL, PRODUCT_NAME, copyright_years
from rich_text import RichText, link, plain
from ui_dialogs import DISCORD_URL, PATREON_URL, WEBSITE_URL
import ui_theme as theme


TITLE = "About " + PRODUCT_NAME
CONTRIBUTORS_ASSET = "contributors_generated.txt"
CONTRIBUTORS_HEADER = "Thanks to project contributors:"
EVERYONE_ELSE = "everyone else who helped"
SEPARATOR = "   •   "
MARQUEE_DIP_PER_SEC = 34
MARQUEE_FRAME_MS = 16
MARQUEE_START_DELAY_MS = 2500


def contributors() -> str:
    path = resolve_asset(CONTRIBUTORS_ASSET)
    names: List[str] = []
    if path is not None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        names = [line.strip() for line in text.splitlines() if line.strip()]
    names.append(EVERYONE_ELSE)
    return SEPARATOR.join(names)


class Marquee(tk.Canvas):

    def __init__(self, parent: tk.Misc, text: str, width: int) -> None:
        self._font = tkfont.nametofont("TkDefaultFont")
        height = self._font.metrics("linespace")
        tk.Canvas.__init__(self, parent, width=width, height=height,
                           background=theme.BG, borderwidth=0,
                           highlightthickness=0)
        self._text = text
        self._cycle = text + SEPARATOR
        self._cycle_w = self._font.measure(self._cycle)
        self._scrolling = self._font.measure(text) > width
        self._offset = 0.0
        self._step = (scaled(self, MARQUEE_DIP_PER_SEC) *
                      MARQUEE_FRAME_MS / 1000.0)
        self._items = []
        if self._scrolling:
            self._items = [self.create_text(0, 0, anchor="nw", text=self._cycle,
                                            fill=theme.FG, font=self._font),
                           self.create_text(self._cycle_w, 0, anchor="nw",
                                            text=self._cycle, fill=theme.FG,
                                            font=self._font)]
            self.after(MARQUEE_START_DELAY_MS, self._tick)
        else:
            self.create_text(0, 0, anchor="nw", text=text, fill=theme.FG,
                             font=self._font)

    def _tick(self) -> None:
        if not self.winfo_exists():
            return
        self._offset = (self._offset + self._step) % float(self._cycle_w)
        x = -int(self._offset)
        self.coords(self._items[0], x, 0)
        self.coords(self._items[1], x + self._cycle_w, 0)
        self.after(MARQUEE_FRAME_MS, self._tick)


class AboutWindow:
    def __init__(self, parent: tk.Misc, device_line: str = "",
                 owner_hwnd: int = 0) -> None:
        self._parent = parent
        self._dlg = tk.Toplevel(parent)
        if parent.winfo_viewable():
            self._dlg.transient(parent)

        self._chrome = chrome = BrandedDialog(self._dlg, TITLE)

        body = chrome.body
        gap = scaled(self._dlg, 10)
        text_w = chrome.body_width

        version, build = resolve_version_parts()
        base = tkfont.nametofont("TkDefaultFont")
        title_font = base.copy()
        title_font.configure(size=int(round(abs(base.cget("size")) * 1.55)),
                             weight="bold")
        version_font = base.copy()
        version_font.configure(size=max(7, int(round(abs(base.cget("size"))
                                                     * 0.95))))

        identity = ttk.Frame(chrome.head)
        identity.pack(side="left", anchor="n", fill="x", expand=True)
        title_row = ttk.Frame(identity)
        title_row.pack(anchor="w")
        ttk.Label(title_row, text=PRODUCT_NAME, font=title_font).pack(
            side="left", anchor="n")
        if version:
            ttk.Label(title_row, text="v" + version, font=version_font,
                      style="Hint.TLabel").pack(side="left", anchor="n",
                                                padx=(scaled(self._dlg, 5), 0))
        if build:
            ttk.Label(identity, text=build, style="Hint.TLabel",
                      wraplength=text_w, justify="left").pack(anchor="w")

        links = ttk.Frame(body)
        links.pack(anchor="w")
        for index, (label, url) in enumerate((("Website", WEBSITE_URL),
                                              ("Discord", DISCORD_URL),
                                              ("Patreon", PATREON_URL))):
            if index:
                ttk.Label(links, text="·", style="Hint.TLabel").pack(
                    side="left", padx=scaled(self._dlg, 6))
            lbl = ttk.Label(links, text=label, foreground=theme.LINK_FG,
                            cursor="hand2")
            lbl.bind("<Button-1>", lambda _e, u=url: webbrowser.open(u))
            lbl.pack(side="left")

        if device_line:
            ttk.Label(body, text=device_line, wraplength=text_w,
                      justify="left").pack(anchor="w", pady=(gap, 0))

        ttk.Label(body, text=CONTRIBUTORS_HEADER, style="Hint.TLabel").pack(
            anchor="w", pady=(gap, 2))
        Marquee(body, contributors(), text_w).pack(anchor="w", fill="x")

        RichText(body, [plain("Copyright (c) " + copyright_years() + " "),
                        link(AUTHOR, lambda: webbrowser.open(AUTHOR_URL))]
                 ).pack(anchor="w", fill="x", pady=(gap, 0))

        chrome.add_button("OK", self._close, default=True)
        self._dlg.bind("<Escape>", lambda _e: self._close())
        self._dlg.protocol("WM_DELETE_WINDOW", self._close)

        chrome.present(parent if parent.winfo_viewable() else None)
        if owner_hwnd:
            theme.set_owner_window(self._dlg, owner_hwnd)
        self._dlg.deiconify()
        self._dlg.lift()
        self._dlg.focus_force()
        self._dlg.grab_set()

    def _close(self) -> None:
        self._dlg.destroy()

    def wait(self) -> None:
        self._parent.wait_window(self._dlg)
