from __future__ import annotations

import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Tuple

from device_state import (DeviceBundle, format_size, running_status,
                          saved_state_info)
from device_model import (TreeSelection, _board_group_key, _device_sort_key,
                          _device_search_haystack, _os_name_has_version,
                          _table_device_label)
from preview_tile import PreviewTile
from board_info import board_soc_cpu, board_soc_label
import ui_theme as theme


def _lighten(color: str, delta: int) -> str:
    r = min(255, int(color[1:3], 16) + delta)
    g = min(255, int(color[3:5], 16) + delta)
    b = min(255, int(color[5:7], 16) + delta)
    return f"#{r:02x}{g:02x}{b:02x}"


class _Card:
    def __init__(self, device: DeviceBundle, frame: tk.Frame,
                 children: List[tk.Widget], status: tk.Label, name: tk.Label,
                 prefix_lbl: tk.Label, soc_lbl: tk.Label, suffix_lbl: tk.Label,
                 tile: PreviewTile):
        self.device = device
        self.frame = frame
        self.children = children
        self.status = status
        self.name = name
        self.prefix_lbl = prefix_lbl
        self.soc_lbl = soc_lbl
        self.suffix_lbl = suffix_lbl
        self.tile = tile


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
        self._cards: Dict[str, _Card] = {}
        self._rows: Dict[str, tk.Widget] = {}
        self._selected: Optional[str] = None

        try:
            dpi = float(parent.winfo_fpixels("1i"))
        except tk.TclError:
            dpi = 96.0
        scale = max(1.0, dpi / 96.0)
        self._tile_w = int(58 * scale)
        self._tile_h = int(46 * scale)
        self._glyph = int(10 * scale)
        self._heading_wrap = int(320 * scale)

        frame = ttk.Frame(parent)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)
        self.frame = frame

        filter_bar = ttk.Frame(frame)
        filter_bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        self.var_search = tk.StringVar(value="")
        self._search_entry = ttk.Entry(filter_bar, textvariable=self.var_search,
                                       width=22)
        self._search_entry.pack(side="right")
        ttk.Label(filter_bar, text="Search:").pack(side="right", padx=(0, 4))
        self.var_search.trace_add("write", lambda *_: self._refill())
        self._search_entry.bind("<Escape>", lambda _e: self.toggle_search())
        self._filter_bar = filter_bar
        self._search_shown = False
        filter_bar.grid_remove()

        canvas = tk.Canvas(frame, bg=theme.BG, highlightthickness=0)
        canvas.grid(row=1, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        vsb.grid(row=1, column=1, sticky="ns")
        canvas.configure(yscrollcommand=vsb.set)
        self._canvas = canvas
        self._inner = tk.Frame(canvas, bg=theme.BG)
        self._inner_id = canvas.create_window((0, 0), window=self._inner,
                                              anchor="nw")
        self._inner.bind(
            "<Configure>",
            lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", self._on_canvas_config)
        self._bind_wheel(canvas)
        self._bind_wheel(self._inner)

    def set_busy(self, busy: bool) -> None:
        pass

    def toggle_search(self) -> None:
        self._search_shown = not self._search_shown
        if self._search_shown:
            self._filter_bar.grid()
            self._search_entry.focus_set()
            return
        self._filter_bar.grid_remove()
        self.var_search.set("")
        self._canvas.focus_set()

    def selection(self) -> TreeSelection:
        if self._selected and self._selected in self._cards:
            return TreeSelection(kind="device",
                                 device=self._cards[self._selected].device)
        return TreeSelection(kind="none")

    def reload(self, devices: List[DeviceBundle]) -> None:
        self.devices = sorted(
            devices, key=lambda d: (_board_group_key(d), _device_sort_key(d)))
        self._refill()

    def select_device(self, name: str) -> None:
        if name in self._cards:
            self._set_selected(name)

    def update_runtime(self) -> None:
        for card in self._cards.values():
            label, fg = self._status_text(card.device)
            if card.status.cget("text") != label:
                card.status.config(text=label, fg=fg)
            card.tile.refresh()
        self._repaint_all()

    def retheme(self) -> None:
        self._canvas.config(bg=theme.BG)
        self._inner.config(bg=theme.BG)
        selected = self._selected
        for key in list(self._rows):
            self._rows.pop(key).destroy()
        self._cards.clear()
        self._refill()
        if selected in self._cards:
            self._set_selected(selected, notify=False)

    def _refill(self) -> None:
        query = self.var_search.get().strip().lower()
        filtered = [d for d in self.devices if d.is_installed
                    and (not query or query in _device_search_haystack(d))]
        title_counts: Dict[Tuple[str, str], int] = {}
        for d in filtered:
            key = (_table_device_label(d), self._os_title(d))
            title_counts[key] = title_counts.get(key, 0) + 1

        desired: List[Tuple[str, str, object, bool]] = []
        last_group: Optional[str] = None
        for d in filtered:
            group = _table_device_label(d)
            if group != last_group:
                desired.append((f"hdr:{group}", "hdr", group, False))
                last_group = group
            collide = title_counts[(group, self._os_title(d))] > 1
            desired.append((f"card:{d.name}", "card", d, collide))

        self._reconcile(desired)

    def _reconcile(self, desired: List[Tuple[str, str, object, bool]]) -> None:
        desired_keys = {key for key, _, _, _ in desired}
        for key in list(self._rows):
            if key not in desired_keys:
                self._rows.pop(key).destroy()
                if key.startswith("card:"):
                    self._cards.pop(key[5:], None)

        for key, kind, payload, collide in desired:
            if key in self._rows:
                if kind == "card":
                    self._update_card(payload, collide)
            elif kind == "card":
                self._rows[key] = self._build_card(payload, collide)
            else:
                self._rows[key] = self._make_header(payload)

        desired_seq = [self._rows[key] for key, _, _, _ in desired]
        if self._inner.pack_slaves() != desired_seq:
            for idx, widget in enumerate(desired_seq):
                order = self._inner.pack_slaves()
                if idx < len(order) and order[idx] is widget:
                    continue
                if idx < len(order):
                    widget.pack_configure(before=order[idx])
                else:
                    widget.pack_configure()

        names = [key[5:] for key, kind, _, _ in desired if kind == "card"]
        if self._selected not in self._cards:
            self._selected = names[0] if names else None
            if self._selected is not None:
                self._set_selected(self._selected, notify=False)
        self._repaint_all()
        self._on_select(self.selection())

    def _make_header(self, group: str) -> tk.Widget:
        hdr = tk.Label(self._inner, text=group, bg=theme.BG, fg=theme.FG,
                       anchor="w",
                       font=("Segoe UI", 13, "bold"))
        hdr.pack(fill="x", padx=2, pady=(9, 3))
        self._bind_wheel(hdr)
        return hdr

    def _card_title(self, d: DeviceBundle, collide: bool) -> str:
        if d.meta.name:
            return d.meta.name
        title = self._os_title(d)
        if collide:
            ce = self._os_ce_version(d)
            if ce:
                title = f"{title}  ·  {ce}"
        return title

    def _card_heading(self, d: DeviceBundle, collide: bool) -> str:
        title = self._card_title(d, collide)
        notes = "  ·  ".join(n.strip() for n in d.meta.os_notes
                             if n and n.strip())
        return f"{title}  ·  {notes}" if notes else title

    def _os_title(self, d: DeviceBundle) -> str:
        meta = d.meta
        edition = (meta.os_name or "").strip() or _table_device_label(d)
        lang = (meta.os_language or "").strip()
        return f"{edition}  ·  {lang}" if lang else edition

    def _os_ce_version(self, d: DeviceBundle) -> str:
        meta = d.meta
        major = meta.os_ver_major or 0
        minor = meta.os_ver_minor or 0
        if not (major or minor):
            return ""
        if _os_name_has_version(meta.os_name or "", major, minor):
            return ""
        ver = f"CE {major}.{minor}"
        if meta.os_ver_build:
            ver += f".{meta.os_ver_build}"
        return ver

    def _card_detail_parts(self, d: DeviceBundle, include_ce: bool):
        parts: List[str] = []
        if include_ce:
            ce = self._os_ce_version(d)
            if ce:
                parts.append(ce)
        if d.meta.os_year:
            parts.append(str(d.meta.os_year))
        soc = board_soc_label(d.meta.board_id)
        size = (format_size(d.remote.unpacked_size) if d.remote
                else format_size(d.rom_size))
        prefix = "  ·  ".join(parts)
        if soc:
            if prefix:
                prefix += "  ·  "
            suffix = ("  ·  " + size) if size else ""
        else:
            if size:
                prefix = (prefix + "  ·  " + size) if prefix else size
            suffix = ""
        return prefix, soc, suffix

    def _badge(self, d: DeviceBundle) -> Optional[tk.PhotoImage]:
        return theme.load_badge(self._icons_dir, board_soc_cpu(d.meta.board_id),
                                self._badge_cache)

    def _build_card(self, d: DeviceBundle, collide: bool) -> tk.Widget:
        card = tk.Frame(self._inner, bg=theme.BG_LIGHTER, highlightthickness=1,
                        highlightbackground=theme.BORDER,
                        highlightcolor=theme.BORDER)
        card.pack(fill="x", padx=2, pady=2)

        tile = PreviewTile(card, self._devices_dir, self._tile_w, self._tile_h,
                           self._glyph, theme.BG_LIGHTER)
        tile.canvas.pack(side="left", padx=(6, 4), pady=5)

        textcol = tk.Frame(card, bg=theme.BG_LIGHTER)
        textcol.pack(side="left", fill="both", expand=True)

        name = tk.Label(textcol, text=self._card_heading(d, collide),
                        bg=theme.BG_LIGHTER, fg=theme.FG, anchor="w",
                        justify="left", wraplength=self._heading_wrap,
                        font=("Segoe UI", 11, "bold"))
        name.pack(fill="x", padx=6, pady=(4, 0))

        detail = tk.Frame(textcol, bg=theme.BG_LIGHTER)
        detail.pack(fill="x", padx=6)
        prefix, soc, suffix = self._card_detail_parts(d, not collide)
        prefix_lbl = tk.Label(detail, text=prefix, bg=theme.BG_LIGHTER,
                              fg=theme.FG_DIM, font=("Segoe UI", 9))
        prefix_lbl.pack(side="left")
        badge = self._badge(d)
        soc_lbl = tk.Label(detail, text=soc, image=badge or "",
                           compound="left" if badge else "none",
                           bg=theme.BG_LIGHTER, fg=theme.FG_DIM,
                           font=("Segoe UI", 9))
        soc_lbl.pack(side="left")
        suffix_lbl = tk.Label(detail, text=suffix, bg=theme.BG_LIGHTER,
                              fg=theme.FG_DIM, font=("Segoe UI", 9))
        suffix_lbl.pack(side="left")

        label, fg = self._status_text(d)
        status = tk.Label(textcol, text=label, bg=theme.BG_LIGHTER, fg=fg,
                          anchor="w", font=("Segoe UI", 9))
        status.pack(fill="x", padx=6, pady=(0, 4))

        bg_children = [card, textcol, detail, name, prefix_lbl, soc_lbl,
                       suffix_lbl, status]
        for w in bg_children:
            w.bind("<Button-1>", lambda _e, n=d.name: self._set_selected(n))
            w.bind("<Double-1>", lambda _e, n=d.name: self._activate(n))
            w.bind("<Button-3>", lambda e, n=d.name: self._context(n, e))
            self._bind_wheel(w)
        tile.canvas.bind("<Button-1>", lambda _e, n=d.name: self._activate(n))
        tile.canvas.bind("<Double-1>", lambda _e: "break")
        tile.canvas.bind("<Button-3>", lambda e, n=d.name: self._context(n, e))
        self._bind_wheel(tile.canvas)
        c = _Card(d, card, bg_children, status, name, prefix_lbl, soc_lbl,
                  suffix_lbl, tile)
        self._cards[d.name] = c
        tile.set_device(d)
        return card

    def _update_card(self, d: DeviceBundle, collide: bool) -> None:
        card = self._cards.get(d.name)
        if card is None:
            return
        card.device = d
        heading = self._card_heading(d, collide)
        if card.name.cget("text") != heading:
            card.name.config(text=heading)
        prefix, soc, suffix = self._card_detail_parts(d, not collide)
        if card.prefix_lbl.cget("text") != prefix:
            card.prefix_lbl.config(text=prefix)
        if card.soc_lbl.cget("text") != soc:
            card.soc_lbl.config(text=soc)
        if card.suffix_lbl.cget("text") != suffix:
            card.suffix_lbl.config(text=suffix)
        label, fg = self._status_text(d)
        if card.status.cget("text") != label:
            card.status.config(text=label, fg=fg)
        card.tile.set_device(d)

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

    def _card_colors(self, d: DeviceBundle) -> Tuple[str, str]:
        if running_status(self._devices_dir / d.name) is not None:
            return theme.CARD_RUNNING_BG, theme.CARD_RUNNING_SEL
        if d.has_update or d.has_cerf_json_update:
            return theme.CARD_UPDATE_BG, theme.CARD_UPDATE_SEL
        return theme.BG_LIGHTER, theme.BG_HOVER

    def _card_bg(self, d: DeviceBundle) -> str:
        return self._card_colors(d)[0]

    def _paint_card(self, card: _Card, selected: bool) -> None:
        base, bright = self._card_colors(card.device)
        fill = bright if selected else base
        border = _lighten(bright, 30) if selected else bright
        card.frame.config(bg=fill, highlightbackground=border,
                          highlightcolor=border)
        for w in card.children:
            if w is not card.frame:
                w.config(bg=fill)
        card.tile.canvas.config(bg=fill)

    def _repaint_all(self) -> None:
        for n, card in self._cards.items():
            self._paint_card(card, n == self._selected)

    def _set_selected(self, name: str, notify: bool = True) -> None:
        if name not in self._cards:
            return
        self._selected = name
        self._repaint_all()
        if notify:
            self._on_select(self.selection())

    def _activate(self, name: str) -> None:
        self._set_selected(name)
        self._on_activate(self.selection())

    def _context(self, name: str, event: tk.Event) -> None:
        self._set_selected(name)
        if self._on_context is not None:
            self._on_context(event)

    def _on_canvas_config(self, e: tk.Event) -> None:
        self._canvas.itemconfigure(self._inner_id, width=e.width)
        self._heading_wrap = max(160, e.width - self._tile_w - 40)
        for card in self._cards.values():
            card.name.config(wraplength=self._heading_wrap)

    def _bind_wheel(self, widget: tk.Widget) -> None:
        widget.bind(
            "<MouseWheel>",
            lambda e: (self._canvas.yview_scroll(int(-e.delta / 120), "units"),
                       "break")[1])
