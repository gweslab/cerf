from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from typing import Callable, Optional, Sequence, Tuple

import ui_theme as theme


Segment = Tuple[str, str, Optional[Callable[[], None]]]


def plain(text: str) -> Segment:
    return (text, "", None)


def bold(text: str) -> Segment:
    return (text, "bold", None)


def link(text: str, action: Callable[[], None]) -> Segment:
    return (text, "link", action)


class RichText(tk.Text):
    def __init__(self, parent: tk.Misc, segments: Sequence[Segment]) -> None:
        tk.Text.__init__(self, parent, wrap="word", relief="flat",
                         borderwidth=0, highlightthickness=0, padx=0, pady=0,
                         background=theme.BG, foreground=theme.FG,
                         inactiveselectbackground=theme.BG,
                         takefocus=0, height=1, width=1)
        base = tkfont.nametofont("TkDefaultFont")
        strong = base.copy()
        strong.configure(weight="bold")
        self._strong = strong
        self.configure(font=base)
        self.tag_configure("bold", font=strong)
        self.tag_configure("link", foreground=theme.LINK_FG, underline=1)

        for index, (text, kind, action) in enumerate(segments):
            if kind == "link":
                name = "link{}".format(index)
                self.insert("end", text, ("link", name))
                self.tag_bind(name, "<Button-1>",
                              lambda _e, a=action: a() if a else None)
                self.tag_bind(name, "<Enter>",
                              lambda _e: self.configure(cursor="hand2"))
                self.tag_bind(name, "<Leave>",
                              lambda _e: self.configure(cursor=""))
            elif kind == "bold":
                self.insert("end", text, ("bold",))
            else:
                self.insert("end", text)

        self.configure(state="disabled")
        self._last_width = -1
        self.bind("<Configure>", self._on_configure)

    def _on_configure(self, event: tk.Event) -> None:
        if event.width == self._last_width:
            return
        self._last_width = event.width
        self.after_idle(self.fit)

    def fit(self) -> None:
        if not self.winfo_exists():
            return
        crossed = self.count("1.0", "end-1c", "update", "displaylines")
        if isinstance(crossed, (tuple, list)):
            crossed = crossed[0] if crossed else 0
        lines = int(crossed or 0) + 1
        if int(self.cget("height")) != lines:
            self.configure(height=lines)
