from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional, Sequence, Tuple, Union

import ui_theme as theme


CHEVRON_TEXT = "»"

MenuEntry = Tuple[str, Callable[[], None], bool]
EntriesFn = Callable[[], Sequence[MenuEntry]]
Label = Union[str, Callable[[], str]]


class _Item:
    def __init__(self, widget: tk.Widget, column: int, gap: int,
                 entries: Optional[EntriesFn]) -> None:
        self.widget = widget
        self.column = column
        self.gap = gap
        self.entries = entries
        self.visible = True

    def width(self) -> int:
        return self.widget.winfo_reqwidth() + self.gap


class OverflowBar:
    def __init__(self, parent: tk.Misc, padding: Tuple[int, int] = (2, 2),
                 gap: int = 0) -> None:
        self.frame = ttk.Frame(parent, padding=padding)
        self._pad_x, self._gap = padding[0], gap
        self._items: List[_Item] = []
        self._columns = 0
        self._spacer: Optional[ttk.Frame] = None
        self._pending_right = False
        self._keep = -1
        self._width = 0

        self._menu = tk.Menu(self.frame, tearoff=0, bd=0,
                             background=theme.BG_FIELD, foreground=theme.FG,
                             activebackground=theme.BG_HOVER,
                             activeforeground=theme.FG)
        self._chevron = ttk.Button(self.frame, text=CHEVRON_TEXT, width=2,
                                   takefocus=False, style="Toolbar.TButton",
                                   command=self._popup)

    def add(self, widget: tk.Widget, label: Optional[Label] = None,
            command: Optional[Callable[[], None]] = None,
            enabled: Optional[Callable[[], bool]] = None,
            entries: Optional[EntriesFn] = None, side: str = "left") -> None:
        if entries is None and label is not None and command is not None:
            entries = self._single(label, command, enabled)
        if side == "right":
            self._add_spacer()
        gap = 0 if not self._items or self._pending_right else self._gap
        self._pending_right = False
        self._place(_Item(widget, self._next_column(), gap, entries))

    def finish(self) -> None:
        self._chevron.grid(row=0, column=self._next_column(), sticky="ns",
                           padx=(self._gap, 0))
        self._chevron.grid_remove()
        self.frame.bind("<Configure>", self._on_configure)

    def refresh(self) -> None:
        self._keep = -1
        self._layout(self._width)

    def retheme(self) -> None:
        self._menu.config(background=theme.BG_FIELD, foreground=theme.FG,
                          activebackground=theme.BG_HOVER,
                          activeforeground=theme.FG)

    @staticmethod
    def _single(label: Label, command: Callable[[], None],
                enabled: Optional[Callable[[], bool]]) -> EntriesFn:
        def entries() -> Sequence[MenuEntry]:
            text = label() if callable(label) else label
            return [(text, command, enabled() if enabled is not None else True)]
        return entries

    def _add_spacer(self) -> None:
        if self._spacer is not None:
            return
        column = self._next_column()
        self._spacer = ttk.Frame(self.frame)
        self._spacer.grid(row=0, column=column, sticky="ew")
        self.frame.columnconfigure(column, weight=1)
        self._pending_right = True

    def _next_column(self) -> int:
        self._columns += 1
        return self._columns - 1

    def _place(self, item: _Item) -> None:
        item.widget.grid(row=0, column=item.column, sticky="ns",
                         padx=(item.gap, 0))
        self._items.append(item)

    def _on_configure(self, event: tk.Event) -> None:
        self._layout(event.width)

    def _fit_count(self, avail: int) -> int:
        widths = [item.width() for item in self._items]
        if sum(widths) + 2 * self._pad_x <= avail:
            return len(self._items)
        budget = (avail - 2 * self._pad_x - self._gap
                  - self._chevron.winfo_reqwidth())
        used, keep = 0, 0
        for i, width in enumerate(widths):
            if used + width > budget:
                break
            used += width
            keep = i + 1
        return keep

    def _layout(self, avail: int) -> None:
        self._width = avail
        if avail <= 1:
            return
        keep = self._fit_count(avail)
        if keep == self._keep:
            return
        self._keep = keep
        for i, item in enumerate(self._items):
            visible = i < keep
            if visible == item.visible:
                continue
            item.visible = visible
            if visible:
                item.widget.grid()
            else:
                item.widget.grid_remove()
        if keep < len(self._items):
            self._chevron.grid()
        else:
            self._chevron.grid_remove()

    def _popup(self) -> None:
        self._menu.delete(0, "end")
        for item in self._items[max(self._keep, 0):]:
            if item.entries is None:
                continue
            for label, command, enabled in item.entries():
                self._menu.add_command(label=label, command=command,
                                       state="normal" if enabled else "disabled")
        try:
            self._menu.tk_popup(self._chevron.winfo_rootx(),
                                self._chevron.winfo_rooty()
                                + self._chevron.winfo_height())
        finally:
            self._menu.grab_release()
