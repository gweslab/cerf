from __future__ import annotations

import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from device_state import DeviceBundle
from board_database import FEATURE_SPECS
from board_info import board_extra_notes, board_features
from side_block import SideBlock
from ui_dialogs import bind_tooltip
import ui_theme as theme


class DetailsPanel:
    def __init__(self, inner: ttk.Frame, icons_dir: Optional[Path],
                 devices_dir: Path,
                 bind_wheel: Callable[[tk.Misc], None],
                 on_package_action: Optional[Callable] = None):
        self._inner = inner
        self._icons_dir = icons_dir
        self._devices_dir = devices_dir
        self._bind_wheel = bind_wheel
        self._on_package_action = on_package_action
        self._icon_cache: Dict[tuple[str, bool], Optional[tk.PhotoImage]] = {}
        self._addon_buttons: List[ttk.Button] = []
        self._addons_enabled = True

        self.meta_block = SideBlock(inner, "Description", row=0)
        meta = self.meta_block.body
        meta.columnconfigure(1, weight=1)

        self.desc_label = ttk.Label(meta, text="", wraplength=220,
                                    justify="left")
        self.desc_label.grid(row=0, column=0, columnspan=2, sticky="w")

        self.source_caption = ttk.Label(meta, text="Source:")
        self.source_caption.grid(row=1, column=0, sticky="w", padx=(0, 8),
                                 pady=(8, 0))
        self.source_value = ttk.Label(meta, wraplength=220, justify="left")
        self.source_value.grid(row=1, column=1, sticky="w", pady=(8, 0))
        self._source_url: Optional[str] = None
        self.source_value.bind("<Button-1>", self._on_source_click)

        self.features_block = SideBlock(inner, "Features", row=1)
        self.features_icons = ttk.Frame(self.features_block.body)
        self.features_icons.pack(anchor="w")

        self.notes_block = SideBlock(inner, "⚠ Notes & quirks", row=2,
                                     warn=True)
        self.notes_label = ttk.Label(self.notes_block.body, text="",
                                     wraplength=260, justify="left")
        self.notes_label.grid(row=0, column=0, sticky="w")

        self.addons_block = SideBlock(inner, "Add-ons", row=3)
        self.addons_body = ttk.Frame(self.addons_block.body)
        self.addons_body.grid(row=0, column=0, sticky="ew")
        self.addons_body.columnconfigure(0, weight=1)

        self._blocks = [self.meta_block, self.features_block,
                        self.notes_block, self.addons_block]
        self.features_block.grid_remove()
        self.desc_label.grid_remove()
        self.notes_block.grid_remove()
        self.addons_block.grid_remove()

    def set_wraplength(self, wrap: int) -> None:
        self.desc_label.config(wraplength=wrap)
        self.notes_label.config(wraplength=wrap)

    def retheme(self) -> None:
        for block in self._blocks:
            block.retheme()

    def show_device(self, device: DeviceBundle) -> None:
        self._update_source(device)
        self._update_description(device)
        has_desc = bool(device.meta.description.strip())
        has_source = (device.meta.source is not None
                      and bool(device.meta.source.name))
        if has_desc or has_source:
            self.meta_block.grid()
        else:
            self.meta_block.grid_remove()
        self._update_features(device)
        self._update_notes(device)
        self._update_packages(device)

    def _update_packages(self, device: DeviceBundle) -> None:
        for child in self.addons_body.winfo_children():
            child.destroy()
        self._addon_buttons = []
        if not device.packages:
            self.addons_block.grid_remove()
            return
        self.addons_block.grid()
        last_cat = None
        r = 0
        for ps in device.packages:
            if ps.category_label != last_cat:
                ttk.Label(self.addons_body, text=ps.category_label,
                          foreground=theme.FG).grid(row=r, column=0, columnspan=2,
                                                    sticky="w", pady=(4, 0))
                last_cat = ps.category_label
                r += 1
            row = ttk.Frame(self.addons_body)
            row.grid(row=r, column=0, columnspan=2, sticky="ew")
            row.columnconfigure(0, weight=1)
            ttk.Label(row, text=ps.remote.name, wraplength=170,
                      justify="left").grid(row=0, column=0, sticky="w")
            if ps.has_update or not ps.installed:
                btn = ttk.Button(row, text="Update" if ps.has_update else "Get",
                                 width=7,
                                 command=lambda p=ps: self._package_action(device, p, "install"))
                btn.grid(row=0, column=1, sticky="e", padx=(4, 0))
                self._addon_buttons.append(btn)
            elif ps.installed:
                btn = ttk.Button(row, text="Delete", width=7, style="Danger.TButton",
                                 command=lambda p=ps: self._package_action(device, p, "delete"))
                btn.grid(row=0, column=1, sticky="e", padx=(4, 0))
                self._addon_buttons.append(btn)
            r += 1
        self._bind_wheel(self.addons_body)
        if not self._addons_enabled:
            for b in self._addon_buttons:
                b.config(state="disabled")

    def set_addons_enabled(self, enabled: bool) -> None:
        self._addons_enabled = enabled
        state = "normal" if enabled else "disabled"
        for b in self._addon_buttons:
            try:
                b.config(state=state)
            except tk.TclError:
                pass

    def _package_action(self, device: DeviceBundle, ps, action: str) -> None:
        if self._on_package_action is not None:
            self._on_package_action(device, ps, action)

    def _update_source(self, device: DeviceBundle) -> None:
        src = device.meta.source
        if src is None or not src.name:
            self.source_caption.grid_remove()
            self.source_value.grid_remove()
            self._source_url = None
            return
        self.source_caption.grid()
        self.source_value.grid()
        self._source_url = src.website or src.origin or None
        if self._source_url:
            self.source_value.config(text=src.name, foreground=theme.LINK_FG,
                                     cursor="hand2")
        else:
            self.source_value.config(text=src.name, foreground=theme.FG,
                                     cursor="")

    def _on_source_click(self, _event: object) -> None:
        if self._source_url:
            webbrowser.open(self._source_url)

    def _update_description(self, device: DeviceBundle) -> None:
        description = device.meta.description.strip()
        if description:
            self.desc_label.config(text=description)
            self.desc_label.grid()
        else:
            self.desc_label.grid_remove()

    def _update_notes(self, device: DeviceBundle) -> None:
        notes: List[str] = list(device.meta.notes)
        notes += board_extra_notes(device.meta.board_id)
        if notes:
            self.notes_label.config(text="\n".join(f"• {n}" for n in notes))
            self.notes_block.grid()
        else:
            self.notes_block.grid_remove()

    def _update_features(self, device: DeviceBundle) -> None:
        for child in self.features_icons.winfo_children():
            child.destroy()
        features = board_features(device.meta.board_id)
        shown = 0
        for key, stem, label in FEATURE_SPECS:
            if key not in features:
                continue
            supported = features[key]
            icon = self._feature_icon(stem, gray=not supported)
            if icon is None:
                continue
            lbl = ttk.Label(self.features_icons, image=icon)
            lbl.image = icon
            lbl.pack(side="left", padx=(0, 8))
            tip = label if supported else f"{label} (unsupported)"
            bind_tooltip(lbl, tip)
            shown += 1
        self._bind_wheel(self.features_icons)
        if shown:
            self.features_block.grid()
        else:
            self.features_block.grid_remove()

    def _feature_icon(self, stem: str, gray: bool) -> Optional[tk.PhotoImage]:
        cache_key = (stem, gray)
        if cache_key in self._icon_cache:
            return self._icon_cache[cache_key]
        icon: Optional[tk.PhotoImage] = None
        if self._icons_dir is not None:
            name = f"{stem}_unsupported.png" if gray else f"{stem}.png"
            path = self._icons_dir / name
            try:
                icon = tk.PhotoImage(file=str(path))
            except tk.TclError:
                icon = None
        self._icon_cache[cache_key] = icon
        return icon
