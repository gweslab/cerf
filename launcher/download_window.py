from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from device_state import DeviceBundle, format_size
from device_model import (GROUP_IID_PREFIX, _device_group_key,
                          _device_group_name, _device_sort_key,
                          _device_search_haystack, _table_device_label,
                          _table_os_label)
from board_info import board_soc_label, board_support_state
from copyright_removal_dialog import (BUTTON_LABEL as COPYRIGHT_BUTTON_LABEL,
                                      ContactsFn, show_copyright_removal)
from screen_geometry import fit_geometry
from sources_dialog import SourcesDialog
import ui_theme as theme

_OSNOTE_PREFIX = "osnote::"

_SORT_DOWNLOADS = "By downloads"
_SORT_REGULAR = "Regular"

ReloadFn = Callable[
    [Callable[[List[DeviceBundle], list, Optional[dict]], None]], None]


class DownloadWindow:
    def __init__(self, parent: tk.Misc, devices: List[DeviceBundle],
                 on_download: Callable[[List[str]], None],
                 abuse_contacts_fn: ContactsFn,
                 reload_fn: Optional[ReloadFn] = None,
                 download_places: Optional[dict] = None) -> None:
        self._on_download = on_download
        self._abuse_contacts_fn = abuse_contacts_fn
        self._reload_fn = reload_fn
        self._places = download_places
        self._checked: set[str] = set()
        self._sizes: Dict[str, int] = {}
        self._payload: Dict[str, DeviceBundle] = {}
        self._group_members: Dict[str, List[str]] = {}
        self._group_labels: Dict[str, str] = {}
        self._device_group: Dict[str, str] = {}

        self._candidates = self._compute_candidates(devices)

        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title("Download ROMs")
        if parent.winfo_viewable():
            dlg.transient(parent)
        body = ttk.Frame(dlg, padding=8)
        body.pack(fill="both", expand=True)
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)

        filt = ttk.Frame(body)
        filt.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        self.var_hide_unsupported = tk.BooleanVar(value=True)
        ttk.Checkbutton(filt, text="Hide unsupported",
                        variable=self.var_hide_unsupported,
                        command=self._refill).pack(side="left")
        ttk.Label(filt, text="Sort:").pack(side="left", padx=(12, 4))
        self.var_sort = tk.StringVar(
            value=_SORT_DOWNLOADS if self._places is not None else _SORT_REGULAR)
        self.sort_combo = ttk.Combobox(
            filt, textvariable=self.var_sort, state="readonly", width=14,
            values=(_SORT_DOWNLOADS, _SORT_REGULAR))
        self.sort_combo.pack(side="left")
        self.sort_combo.bind("<<ComboboxSelected>>", lambda *_: self._refill())
        self._sync_sort_availability()
        self.btn_sources = ttk.Button(filt, text="Sources…",
                                      command=self._open_sources)
        self.btn_sources.pack(side="right", padx=(8, 0))
        self.var_search = tk.StringVar(value="")
        ttk.Entry(filt, textvariable=self.var_search, width=24).pack(side="right")
        ttk.Label(filt, text="Search:").pack(side="right", padx=(0, 4))
        self.var_search.trace_add("write", lambda *_: self._refill())

        columns = ("soc", "size")
        tree = ttk.Treeview(body, columns=columns, show="tree headings",
                            selectmode="none")
        tree.heading("#0", text="☐  Device / OS")
        tree.heading("soc", text="SoC")
        tree.heading("size", text="Size")
        tree.column("#0", width=640, minwidth=320, anchor="w", stretch=True)
        tree.column("soc", width=150, minwidth=100, anchor="w", stretch=True)
        tree.column("size", width=90, minwidth=70, anchor="e", stretch=False)
        tree.grid(row=1, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        vsb.grid(row=1, column=1, sticky="ns")
        tree.configure(yscrollcommand=vsb.set)
        tree.tag_configure("group", background=theme.GROUP_BG, foreground=theme.FG)
        tree.tag_configure("osnote", foreground=theme.FG_DIM)
        tree.bind("<Button-1>", self._on_click)
        self.tree = tree

        footer = ttk.Frame(body)
        footer.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        footer.columnconfigure(1, weight=1)
        ttk.Button(footer, text=COPYRIGHT_BUTTON_LABEL,
                   command=self._open_copyright_removal).grid(
            row=0, column=0, sticky="w")
        self.summary = ttk.Label(footer, text="")
        self.summary.grid(row=0, column=1, sticky="w", padx=(12, 0))
        ttk.Button(footer, text="Cancel", command=dlg.destroy).grid(
            row=0, column=2, padx=(0, 6))
        self.btn_download = ttk.Button(footer, text="Download",
                                       style="Download.TButton",
                                       command=self._confirm)
        self.btn_download.grid(row=0, column=3)

        self._refill()
        dlg.update_idletasks()
        theme.apply_titlebar(dlg)
        try:
            scale = max(1.0, float(dlg.winfo_fpixels("1i")) / 96.0)
        except tk.TclError:
            scale = 1.0
        dlg.minsize(int(360 * scale), int(240 * scale))
        fit_geometry(dlg, 1000, 620, parent=parent)
        dlg.grab_set()

    def _compute_candidates(self, devices: List[DeviceBundle]) -> List[DeviceBundle]:
        return sorted(
            [d for d in devices if d.remote is not None and not d.is_installed],
            key=lambda d: (_device_group_key(d), _device_sort_key(d)))

    def _open_copyright_removal(self) -> None:
        show_copyright_removal(self._dlg, self._abuse_contacts_fn())

    def _open_sources(self) -> None:
        SourcesDialog(self._dlg, self._sources_changed)

    def _sources_changed(self) -> None:
        if self._reload_fn is None:
            return
        self.btn_sources.config(state="disabled")
        self._reload_fn(self._reloaded)

    def _reloaded(self, devices: List[DeviceBundle], errors: list,
                  places: Optional[dict]) -> None:
        self._places = places
        self._candidates = self._compute_candidates(devices)
        self._checked.intersection_update(d.key for d in self._candidates)
        self.btn_sources.config(state="normal")
        self._sync_sort_availability()
        self._refill()

    def _sync_sort_availability(self) -> None:
        if self._places is None:
            self.var_sort.set(_SORT_REGULAR)
            self.sort_combo.configure(state="disabled")
        else:
            self.sort_combo.configure(state="readonly")

    def _sort_mode(self) -> str:
        if self._places is not None and self.var_sort.get() == _SORT_DOWNLOADS:
            return "downloads"
        return "regular"

    def _place(self, d: DeviceBundle) -> Optional[int]:
        if self._places is None or d.remote is None:
            return None
        return self._places.get((d.remote.repo_url, d.remote.name))

    def _place_key(self, d: DeviceBundle) -> tuple:
        place = self._place(d)
        return (place is None, place if place is not None else 0,
                _device_sort_key(d))

    def _visible_candidates(self) -> List[DeviceBundle]:
        hide_unsupported = self.var_hide_unsupported.get()
        query = self.var_search.get().strip().lower()
        return [d for d in self._candidates
                if not (hide_unsupported and
                        board_support_state(d.meta.board_id) is not True)
                and (not query or query in _device_search_haystack(d))]

    def _check_glyph(self, name: str) -> str:
        return "☑  " if name in self._checked else "☐  "

    def _group_glyph(self, gid: str) -> str:
        members = self._group_members.get(gid, [])
        if members and all(n in self._checked for n in members):
            return "☑  "
        if any(n in self._checked for n in members):
            return "▣  "
        return "☐  "

    def _refresh_group_text(self, gid: str) -> None:
        self.tree.item(gid, text=self._group_glyph(gid) +
                       self._group_labels[gid])

    def _refill(self) -> None:
        tree = self.tree
        tree.delete(*tree.get_children())
        self._payload.clear()
        self._group_members = {}
        self._group_labels = {}
        self._device_group = {}
        visible = self._visible_candidates()
        if self._sort_mode() == "downloads":
            group_rank: Dict[str, int] = {}
            for d in visible:
                place = self._place(d)
                prev = group_rank.get(_device_group_name(d))
                if place is not None and (prev is None or place < prev):
                    group_rank[_device_group_name(d)] = place

            def downloads_key(d: DeviceBundle) -> tuple:
                rank = group_rank.get(_device_group_name(d))
                return (rank is None, rank if rank is not None else 0,
                        _device_group_key(d), self._place_key(d))
            visible.sort(key=downloads_key)
        groups: Dict[str, str] = {}
        for d in visible:
            name = _device_group_name(d)
            gid = groups.get(name)
            if gid is None:
                gid = GROUP_IID_PREFIX + name
                tree.insert("", "end", iid=gid, text="", open=True,
                            tags=("group",))
                groups[name] = gid
                self._group_members[gid] = []
                self._group_labels[gid] = _table_device_label(d)
            self._insert_device_row(gid, d)
            self._group_members[gid].append(d.key)
            self._device_group[d.key] = gid
        for gid in self._group_members:
            self._refresh_group_text(gid)
        self._update_summary()

    def _insert_device_row(self, parent: str, d: DeviceBundle) -> None:
        tree = self.tree
        self._sizes[d.key] = d.remote.archive_size or 0
        soc = board_soc_label(d.meta.board_id)
        tree.insert(parent, "end", iid=d.key, open=bool(d.meta.os_notes),
                    text=self._check_glyph(d.key) + _table_os_label(d),
                    values=(soc, format_size(d.remote.archive_size) or ""))
        self._payload[d.key] = d
        for i, note in enumerate(d.meta.os_notes):
            tree.insert(d.key, "end",
                        iid=f"{_OSNOTE_PREFIX}{d.key}::{i}",
                        text=f"↳ {note}", values=("", ""),
                        tags=("osnote",))

    def _on_click(self, event: tk.Event) -> None:
        if self.tree.identify("region", event.x, event.y) not in ("tree", "cell"):
            return
        if "indicator" in self.tree.identify_element(event.x, event.y):
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid in self._group_members:
            members = self._group_members[iid]
            check = not (members and all(n in self._checked for n in members))
            for n in members:
                self._checked.add(n) if check else self._checked.discard(n)
                self.tree.item(n, text=self._check_glyph(n) +
                               _table_os_label(self._payload[n]))
            self._refresh_group_text(iid)
            self._update_summary()
            return
        if iid not in self._payload:
            return
        if iid in self._checked:
            self._checked.discard(iid)
        else:
            self._checked.add(iid)
        self.tree.item(iid, text=self._check_glyph(iid) +
                       _table_os_label(self._payload[iid]))
        gid = self._device_group.get(iid)
        if gid:
            self._refresh_group_text(gid)
        self._update_summary()

    def _update_summary(self) -> None:
        total = sum(self._sizes.get(n, 0) for n in self._checked)
        n = len(self._checked)
        self.summary.config(
            text=f"{n} selected · {format_size(total)}" if n else "Nothing selected")
        self.btn_download.config(state=("normal" if n else "disabled"))

    def _confirm(self) -> None:
        keys = [d.key for d in self._candidates if d.key in self._checked]
        self._dlg.destroy()
        if keys:
            self._on_download(keys)
