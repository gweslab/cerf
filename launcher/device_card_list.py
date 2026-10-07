from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Tuple, Union

from board_database import sort_text
from board_info import board_soc_cpu
from device_card import DETAIL_FONT, DeviceCard
from device_card_text import card_detail_parts, card_heading, os_title
from device_model import (TreeSelection, _board_group_key, _device_sort_key,
                          _device_search_haystack, _table_device_label)
from device_state import DeviceBundle, format_size, running_status, \
    saved_state_info
from rounded_style import CARD_MARGIN_X
from sv_elements import PAGE_SCROLLBAR_STYLE
from ui_scroll import fit_scrollregion
import ui_theme as theme

HOVER_BLEND = 0.5
HEADER_FONT = ("Segoe UI", 13, "bold")
HEADER_PAD_TOP = 11
HEADER_PAD_BOTTOM = 5
MIN_WRAP = 160
WRAP_RESERVE = 36


class _Header:
    def __init__(self, canvas: tk.Canvas, text: str) -> None:
        self.canvas = canvas
        self.item = canvas.create_text(0, 0, anchor="nw", text=text,
                                       font=HEADER_FONT, fill=theme.FG)

    def layout(self, y: int) -> int:
        self.canvas.coords(self.item, CARD_MARGIN_X, y + HEADER_PAD_TOP)
        box = self.canvas.bbox(self.item)
        return box[3] + HEADER_PAD_BOTTOM

    def delete(self) -> None:
        self.canvas.delete(self.item)


Row = Union[_Header, DeviceCard]


class DeviceCardList:
    def __init__(self, parent: ttk.Frame,
                 on_select: Callable[[TreeSelection], None],
                 on_activate: Callable[[TreeSelection], None],
                 devices_dir: Path,
                 icons_dir: Optional[Path] = None,
                 on_context: Optional[Callable[[tk.Event], None]] = None):
        self._on_select = on_select
        self._on_activate = on_activate
        self._on_context = on_context
        self._devices_dir = devices_dir
        self._icons_dir = icons_dir
        self._badge_cache: Dict[str, Optional[tk.PhotoImage]] = {}
        self.devices: List[DeviceBundle] = []
        self._cards: Dict[str, DeviceCard] = {}
        self._rows: Dict[str, Row] = {}
        self._order: List[str] = []
        self._selected: Optional[str] = None
        self._hovered: Optional[str] = None
        self._width = 0
        self._tag_serial = 0
        self._query = ""

        try:
            dpi = float(parent.winfo_fpixels("1i"))
        except tk.TclError:
            dpi = 96.0
        scale = max(1.0, dpi / 96.0)
        self._tile_size = (int(58 * scale), int(46 * scale))
        self._glyph = int(10 * scale)
        self._line_h = tkfont.Font(parent, font=DETAIL_FONT).metrics(
            "linespace")

        frame = ttk.Frame(parent, style="Page.TFrame")
        frame.grid(row=0, column=0, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.frame = frame

        canvas = tk.Canvas(frame, bg=theme.PAGE_BG, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview,
                            style=PAGE_SCROLLBAR_STYLE)
        vsb.grid(row=0, column=1, sticky="ns")
        canvas.configure(yscrollcommand=vsb.set)
        self._canvas = canvas
        canvas.bind("<Configure>", self._on_canvas_config)
        canvas.bind("<MouseWheel>", self._on_wheel)
        canvas.bind("<Button-1>", self._on_click)
        canvas.bind("<Double-1>", self._on_double)
        canvas.bind("<Button-3>", self._on_right)
        canvas.bind("<Motion>", self._on_motion)
        canvas.bind("<Leave>", lambda _e: self._set_hovered(None))

    def set_busy(self, busy: bool) -> None:
        pass

    def set_query(self, text: str) -> None:
        self._query = text.strip().lower()
        self._refill()

    def selection(self) -> TreeSelection:
        if self._selected and self._selected in self._cards:
            return TreeSelection(kind="device",
                                 device=self._cards[self._selected].device)
        return TreeSelection(kind="none")

    def reload(self, devices: List[DeviceBundle]) -> None:
        self.devices = sorted(
            devices, key=lambda d: (_board_group_key(d),
                                    sort_text(_table_device_label(d)),
                                    _device_sort_key(d)))
        self._refill()

    def select_device(self, name: str) -> None:
        if name in self._cards:
            self._set_selected(name)

    def update_runtime(self) -> None:
        for card in self._cards.values():
            card.set_status(*self._status_text(card.device))
            card.tile.refresh()
        self._repaint_all()

    def retheme(self) -> None:
        self._canvas.config(bg=theme.PAGE_BG)
        selected = self._selected
        for key in list(self._rows):
            self._rows.pop(key).delete()
        self._cards.clear()
        self._order = []
        self._refill()
        if selected in self._cards:
            self._set_selected(selected, notify=False)

    def _refill(self) -> None:
        query = self._query
        filtered = [d for d in self.devices if d.is_installed
                    and (not query or query in _device_search_haystack(d))]
        title_counts: Dict[Tuple[str, str], int] = {}
        for d in filtered:
            key = (_table_device_label(d), os_title(d))
            title_counts[key] = title_counts.get(key, 0) + 1

        desired: List[Tuple[str, object, bool]] = []
        last_group: Optional[str] = None
        header_counts: Dict[str, int] = {}
        for d in filtered:
            group = _table_device_label(d)
            if group != last_group:
                n = header_counts.get(group, 0)
                header_counts[group] = n + 1
                desired.append((f"hdr:{n}:{group}", group, False))
                last_group = group
            collide = title_counts[(group, os_title(d))] > 1
            desired.append((f"card:{d.name}", d, collide))
        self._reconcile(desired)

    def _reconcile(self, desired: List[Tuple[str, object, bool]]) -> None:
        wanted = {key for key, _, _ in desired}
        for key in list(self._rows):
            if key not in wanted:
                self._rows.pop(key).delete()
                if key.startswith("card:"):
                    self._cards.pop(key[5:], None)

        for key, payload, collide in desired:
            row = self._rows.get(key)
            if isinstance(row, DeviceCard):
                self._fill_card(row, payload, collide)
            elif row is None:
                self._rows[key] = (self._build_card(payload, collide)
                                   if key.startswith("card:")
                                   else _Header(self._canvas, payload))
        self._order = [key for key, _, _ in desired]
        self._layout()

        names = [key[5:] for key in self._order if key.startswith("card:")]
        if self._selected not in self._cards:
            self._selected = names[0] if names else None
        if self._hovered not in self._cards:
            self._hovered = None
        self._repaint_all()
        self._on_select(self.selection())

    def _build_card(self, d: DeviceBundle, collide: bool) -> DeviceCard:
        self._tag_serial += 1
        card = DeviceCard(self._canvas, "card{}".format(self._tag_serial), d,
                          collide, self._devices_dir, self._tile_size,
                          self._glyph, self._line_h)
        card.set_badge(theme.load_badge(self._icons_dir,
                                        board_soc_cpu(d.meta.board_id),
                                        self._badge_cache))
        self._cards[d.name] = card
        self._fill_card(card, d, collide)
        return card

    def _fill_card(self, card: DeviceCard, d: DeviceBundle,
                   collide: bool) -> None:
        card.device = d
        card.collide = collide
        prefix, soc, suffix = card_detail_parts(d, not collide)
        card.set_texts(card_heading(d, collide), prefix, soc, suffix)
        card.set_status(*self._status_text(d))
        card.tile.set_device(d)

    def _layout(self) -> None:
        width = self._width or self._canvas.winfo_width()
        if width <= 1:
            return
        wrap = max(MIN_WRAP, width - 2 * CARD_MARGIN_X - self._tile_size[0]
                   - WRAP_RESERVE)
        y = 0
        for i, key in enumerate(self._order):
            row = self._rows[key]
            if isinstance(row, DeviceCard):
                first = i == 0 or not isinstance(
                    self._rows[self._order[i - 1]], DeviceCard)
                last = (i + 1 == len(self._order)
                        or not isinstance(self._rows[self._order[i + 1]],
                                          DeviceCard))
                y = row.layout(y, width, wrap, first, last)
            else:
                y = row.layout(y)
        fit_scrollregion(self._canvas, HEADER_PAD_TOP)

    def _status_text(self, d: DeviceBundle) -> Tuple[str, str]:
        dirpath = self._devices_dir / d.name
        if running_status(dirpath) is not None:
            return "● Running", theme.FG
        info = saved_state_info(dirpath)
        if info is not None:
            when = datetime.fromtimestamp(info.saved_at).strftime("%d.%m %H:%M")
            size = format_size(info.size)
            label = f"◷ Saved {when}"
            if size:
                label += f" · {size}"
            return label, theme.FG_DIM
        return "Powered off", theme.FG_DIM

    def _card_colors(self, d: DeviceBundle) -> Tuple[str, str, str]:
        if running_status(self._devices_dir / d.name) is not None:
            base, bright = theme.CARD_RUNNING_BG, theme.CARD_RUNNING_SEL
        elif d.has_update or d.has_cerf_json_update:
            base, bright = theme.CARD_UPDATE_BG, theme.CARD_UPDATE_SEL
        else:
            return theme.BG, theme.CARD_HOVER, theme.BG_HOVER
        return base, theme.blend(base, bright, HOVER_BLEND), bright

    def _paint(self, name: str) -> None:
        card = self._cards[name]
        base, hover, selected = self._card_colors(card.device)
        if name == self._selected:
            card.paint(selected)
        elif name == self._hovered:
            card.paint(hover)
        else:
            card.paint(base)

    def _repaint_all(self) -> None:
        for name in self._cards:
            self._paint(name)

    def _set_selected(self, name: str, notify: bool = True) -> None:
        if name not in self._cards:
            return
        previous, self._selected = self._selected, name
        for n in (previous, name):
            if n in self._cards:
                self._paint(n)
        if notify:
            self._on_select(self.selection())

    def _set_hovered(self, name: Optional[str]) -> None:
        previous = self._hovered
        if previous == name:
            return
        self._hovered = name
        for n in (previous, name):
            if n in self._cards:
                self._paint(n)

    def _hit(self, event: tk.Event) -> Tuple[Optional[str], Optional[str]]:
        x = self._canvas.canvasx(event.x)
        y = self._canvas.canvasy(event.y)
        for name, card in self._cards.items():
            part = card.hit(x, y)
            if part is not None:
                return name, part
        return None, None

    def _on_motion(self, event: tk.Event) -> None:
        name, part = self._hit(event)
        self._set_hovered(name)
        cursor = "hand2" if part == "tile" else ""
        if str(self._canvas.cget("cursor")) != cursor:
            self._canvas.config(cursor=cursor)

    def _on_click(self, event: tk.Event) -> None:
        name, part = self._hit(event)
        if name is None:
            return
        if part == "tile":
            self._activate(name)
        else:
            self._set_selected(name)

    def _on_double(self, event: tk.Event) -> None:
        name, part = self._hit(event)
        if name is not None and part == "card":
            self._activate(name)

    def _on_right(self, event: tk.Event) -> None:
        name, _ = self._hit(event)
        if name is None:
            return
        self._set_selected(name)
        if self._on_context is not None:
            self._on_context(event)

    def _activate(self, name: str) -> None:
        self._set_selected(name)
        self._on_activate(self.selection())

    def _on_canvas_config(self, e: tk.Event) -> None:
        if e.width != self._width:
            self._width = e.width
            self._layout()
        else:
            fit_scrollregion(self._canvas, HEADER_PAD_TOP)

    def _on_wheel(self, e: tk.Event) -> str:
        self._canvas.yview_scroll(int(-e.delta / 120), "units")
        return "break"
