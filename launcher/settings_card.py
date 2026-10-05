from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional, Sequence

from branded_dialog import scaled
from rich_text import RichText, Segment
from rounded_style import rounded_frame
import ui_theme as theme

CONTROL_DIP = 250
PATH_DIP = 440
WRAP_DIP = 340
ROW_PAD_X_DIP = 12
ROW_PAD_Y_DIP = 8
CONTROL_GAP_DIP = 16
SECTION_GAP_DIP = 16
SECTION_TO_GROUP_DIP = 6
GROUP_GAP_DIP = 10
INFO_ICON_DIP = 18

Description = Optional[Sequence[Segment]]


def control_width(widget: tk.Misc) -> int:
    return scaled(widget, CONTROL_DIP)


def path_width(widget: tk.Misc) -> int:
    return scaled(widget, PATH_DIP)


def row_padding(widget: tk.Misc) -> tuple:
    return (scaled(widget, ROW_PAD_X_DIP), scaled(widget, ROW_PAD_Y_DIP))


def wrapping_label(parent: tk.Misc, text: str,
                   style: str = "Hint.TLabel") -> ttk.Label:
    label = ttk.Label(parent, text=text, style=style, justify="left",
                      wraplength=scaled(parent, WRAP_DIP))
    label.bind("<Configure>",
               lambda e: label.config(wraplength=max(1, e.width)))
    return label


def _description(parent: tk.Misc, segments: Sequence[Segment]) -> tk.Widget:
    if all(kind != "link" for _text, kind, _action in segments):
        return ttk.Label(parent, style="Hint.TLabel",
                         text="".join(t for t, _k, _a in segments))
    return RichText(parent, segments, foreground=theme.FG_DIM)


def switch(parent: tk.Misc, variable: tk.BooleanVar,
           command: Optional[Callable[[], None]] = None) -> ttk.Checkbutton:
    return ttk.Checkbutton(parent, style="Switch.TCheckbutton",
                           variable=variable, command=command)


class SettingsRow:
    def __init__(self, parent: tk.Misc, title: str,
                 description: Description = None) -> None:
        self.frame = ttk.Frame(parent, padding=row_padding(parent))
        self.frame.columnconfigure(0, weight=1)
        text = ttk.Frame(self.frame)
        text.grid(row=0, column=0, sticky="ew")
        text.columnconfigure(0, weight=1)
        ttk.Label(text, text=title).grid(row=0, column=0, sticky="w")
        if description:
            _description(text, description).grid(row=1, column=0,
                                                 sticky="ew")

    def control(self, widget: tk.Widget, wide: bool = True) -> None:
        if wide:
            self.frame.columnconfigure(1, minsize=control_width(self.frame))
        widget.grid(row=0, column=1, sticky="ew" if wide else "e",
                    padx=(scaled(self.frame, CONTROL_GAP_DIP), 0))


class SettingsGroup:
    def __init__(self, parent: tk.Misc) -> None:
        self.frame = rounded_frame(parent, theme.BG, theme.CARD_BORDER,
                                   theme.PAGE_BG)
        self.frame.columnconfigure(0, weight=1)
        self._next = 0

    def _place(self, widget: tk.Widget) -> None:
        if self._next:
            tk.Frame(self.frame, height=1, bd=0, bg=theme.CARD_BORDER).grid(
                row=self._next, column=0, sticky="ew")
        self._next += 1
        widget.grid(row=self._next, column=0, sticky="ew")
        self._next += 1

    def row(self, title: str, description: Description = None) -> SettingsRow:
        row = SettingsRow(self.frame, title, description)
        self._place(row.frame)
        return row

    def body(self) -> ttk.Frame:
        frame = ttk.Frame(self.frame, padding=row_padding(self.frame))
        frame.columnconfigure(0, weight=1)
        self._place(frame)
        return frame

    def note(self, text: str) -> None:
        frame = ttk.Frame(self.frame, padding=row_padding(self.frame))
        frame.columnconfigure(1, weight=1)
        size = scaled(frame, INFO_ICON_DIP)
        icon = tk.Canvas(frame, width=size, height=size, bd=0,
                         highlightthickness=0, bg=theme.BG)
        icon.create_oval(1, 1, size - 1, size - 1, outline=theme.FG_DIM)
        icon.create_text(size / 2.0, size / 2.0, text="i",
                         fill=theme.FG_DIM, font=("Segoe UI", 8, "bold"))
        icon.grid(row=0, column=0, sticky="n",
                  padx=(0, scaled(frame, ROW_PAD_X_DIP)))
        wrapping_label(frame, text).grid(row=0, column=1, sticky="ew")
        self._place(frame)


class SettingsColumn:
    def __init__(self, parent: tk.Misc) -> None:
        self.frame = ttk.Frame(parent, style="Page.TFrame")
        self.frame.columnconfigure(0, weight=1)
        self._next = 0
        self._after_section = False

    def section(self, title: str) -> None:
        top = scaled(self.frame, SECTION_GAP_DIP) if self._next else 0
        ttk.Label(self.frame, text=title, style="Section.TLabel").grid(
            row=self._next, column=0, sticky="w", pady=(top, 0))
        self._next += 1
        self._after_section = True

    def place(self, widget: tk.Widget) -> None:
        if self._after_section:
            top = scaled(self.frame, SECTION_TO_GROUP_DIP)
        elif self._next:
            top = scaled(self.frame, GROUP_GAP_DIP)
        else:
            top = 0
        widget.grid(row=self._next, column=0, sticky="ew", pady=(top, 0))
        self._next += 1
        self._after_section = False

    def group(self) -> SettingsGroup:
        group = SettingsGroup(self.frame)
        self.place(group.frame)
        return group

    def column(self) -> "SettingsColumn":
        column = SettingsColumn(self.frame)
        self.place(column.frame)
        return column
