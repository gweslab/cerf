from __future__ import annotations

import tkinter as tk
from typing import Dict, Optional, Tuple

GRIP_CURSOR = "sb_h_double_arrow"
GRIP_WIDTH = 6


class SashGrip:
    def __init__(self, paned: tk.PanedWindow, sash: int, pane: tk.Misc,
                 width: int = GRIP_WIDTH) -> None:
        self._paned = paned
        self._sash = sash
        self._pane = pane
        self._width = width
        self._tag = "SashGrip{}".format(id(self))
        self._cursors: Dict[str, str] = {}
        self._drag: Optional[Tuple[int, int, int]] = None
        for sequence, handler in (("<Motion>", self._on_motion),
                                  ("<Leave>", self._on_leave),
                                  ("<Button-1>", self._on_press),
                                  ("<B1-Motion>", self._on_drag),
                                  ("<ButtonRelease-1>", self._on_release)):
            pane.bind_class(self._tag, sequence, handler)

    def attach(self, *widgets: tk.Misc) -> None:
        for widget in widgets:
            self._cursors[str(widget)] = str(widget.cget("cursor"))
            widget.bindtags((self._tag,) + widget.bindtags())

    def _inside(self, event: tk.Event) -> bool:
        return 0 <= event.x_root - self._pane.winfo_rootx() < self._width

    def _show_grip(self, widget: tk.Misc, grip: bool) -> None:
        cursor = GRIP_CURSOR if grip else self._cursors[str(widget)]
        if str(widget.cget("cursor")) != cursor:
            widget.configure(cursor=cursor)

    def _on_motion(self, event: tk.Event) -> None:
        if self._drag is None:
            self._show_grip(event.widget, self._inside(event))

    def _on_leave(self, event: tk.Event) -> None:
        if self._drag is None:
            self._show_grip(event.widget, False)

    def _on_press(self, event: tk.Event) -> Optional[str]:
        if not self._inside(event):
            return None
        x, y = self._paned.sash_coord(self._sash)
        self._drag = (event.x_root, x, y)
        return "break"

    def _on_drag(self, event: tk.Event) -> Optional[str]:
        if self._drag is None:
            return None
        start, x, y = self._drag
        self._paned.sash_place(self._sash, x + event.x_root - start, y)
        return "break"

    def _on_release(self, event: tk.Event) -> Optional[str]:
        if self._drag is None:
            return None
        self._drag = None
        self._show_grip(event.widget, self._inside(event))
        return "break"
