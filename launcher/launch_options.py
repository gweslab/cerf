from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import List, Optional

from pathlib import Path

from customizations_block import CustomizationsBlock
from device_state import DeviceBundle
from board_info import board_configurable_screen, board_features
from color_schemes import color_scheme_supported_for_os
from persisted_options import (PERSIST_KEYS, effective_values, persist_subset)
from share_folder_block import ShareFolderBlock
from ui_dialogs import show_guest_additions_help
from saved_state_warning import SavedStateEditWarning


class LaunchOptionsPanel:
    def __init__(self, inner: ttk.Frame, parent_window: tk.Misc,
                 devices_dir: Path, row: int):
        self._window = parent_window
        self._device: Optional[DeviceBundle] = None
        self._devices_dir = devices_dir
        self._device_dir: Optional[Path] = None
        self._baseline: dict = {}
        self._restoring = False
        self._guest_additions_available = True
        self._guest_additions_locked = False
        self._color_scheme_available = True
        self._locked = False
        self._saved_state_warning = SavedStateEditWarning(parent_window)

        container = ttk.Frame(inner)
        container.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        container.columnconfigure(0, weight=1)
        self.frame = container
        self.var_log_all = tk.BooleanVar(value=False)
        self.var_no_net = tk.BooleanVar(value=False)
        self.var_full_screen = tk.BooleanVar(value=False)
        self.var_guest_additions = tk.BooleanVar(value=False)

        cfg = ttk.LabelFrame(container, text="Configuration", padding=8)
        cfg.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        cfg.columnconfigure(0, weight=1)

        guest = self.guest_block = ttk.Frame(cfg)
        guest.grid(row=0, column=0, sticky="ew")
        guest.columnconfigure(0, weight=1)
        self.ga_check = ttk.Checkbutton(guest, text="Enable guest additions",
                                        variable=self.var_guest_additions,
                                        command=self._on_guest_additions_changed,
                                        style="Guest.TCheckbutton")
        self.ga_check.grid(row=0, column=0, sticky="w")
        self.ga_help = ttk.Button(guest, text="?", width=2, style="Help.TButton",
                                  command=lambda: show_guest_additions_help(self._window))
        self.ga_help.grid(row=0, column=1, sticky="e")
        ttk.Label(guest, text="(might be unstable)",
                  style="Hint.TLabel").grid(row=1, column=0, columnspan=2,
                                            sticky="w")

        self.guest_sep = ttk.Separator(cfg, orient="horizontal")
        self.guest_sep.grid(row=1, column=0, sticky="ew", pady=8)

        self.share = ShareFolderBlock(cfg, parent_window, self._persist, row=2)
        self.share_sep = ttk.Separator(cfg, orient="horizontal")
        self.share_sep.grid(row=3, column=0, sticky="ew", pady=8)

        self.custom = CustomizationsBlock(cfg, parent_window, self._persist,
                                          row=4)
        self.custom_sep = ttk.Separator(cfg, orient="horizontal")
        self.custom_sep.grid(row=5, column=0, sticky="ew", pady=8)

        self.fullscreen_check = ttk.Checkbutton(cfg, text="Borderless full screen",
                                                variable=self.var_full_screen,
                                                command=self._persist)
        self.fullscreen_check.grid(row=6, column=0, sticky="w")

        ttk.Separator(cfg, orient="horizontal").grid(row=7, column=0,
                                                     sticky="ew", pady=8)

        self.logall_check = ttk.Checkbutton(cfg, text="Enable all log channels",
                                            variable=self.var_log_all)
        self.logall_check.grid(row=8, column=0, sticky="w")
        self.nonet_check = ttk.Checkbutton(cfg, text="Disable network backend",
                                           variable=self.var_no_net,
                                           command=self._persist)
        self.nonet_check.grid(row=9, column=0, sticky="w")

        self._lockable = ([self.ga_check, self.ga_help]
                          + self.share.lockables() + self.custom.lockables()
                          + [self.fullscreen_check, self.logall_check,
                             self.nonet_check])
        self.refresh_resolution_state()

    def set_locked(self, locked: bool) -> None:
        if self._locked == locked:
            return
        self._locked = locked
        for w in self._lockable:
            try:
                w.config(state="disabled" if locked else "normal")
            except tk.TclError:
                pass
        self.refresh_resolution_state()

    def set_device(self, device: Optional[DeviceBundle]) -> None:
        self._device = device
        self._device_dir = None
        if device is not None and device.is_installed:
            self._device_dir = self._devices_dir / device.name
        self._baseline, eff = effective_values(
            self._device_dir,
            device.default_screen_width if device is not None else None,
            device.default_screen_height if device is not None else None)
        self._guest_additions_available = self._resolve_guest_additions_available(device)
        self._guest_additions_locked = bool(device is not None
                                            and device.meta.forbid_guest_additions)
        self._color_scheme_available = (
            device is None or color_scheme_supported_for_os(device.meta.os_name))
        if self._guest_additions_locked:
            for k in ("guest_additions", "color_scheme", "width", "height",
                      "dpi", "font_size", "bpp", "share_folder"):
                if k in self._baseline:
                    eff[k] = self._baseline[k]
                else:
                    eff.pop(k, None)
        self._restoring = True
        try:
            self.var_no_net.set(not eff["network_enabled"])
            self.var_guest_additions.set(eff["guest_additions"]
                                         and self._guest_additions_available)
            self.var_full_screen.set(eff["full_screen"])
            self.share.restore(eff)
            self.custom.restore(eff)
        finally:
            self._restoring = False
        self.refresh_resolution_state()

    def _resolve_guest_additions_available(self,
                                           device: Optional[DeviceBundle]) -> bool:
        if device is None:
            return True
        if device.meta.os_ver_major == 1:
            return False
        return board_features(device.meta.board_id).get("guest_additions") is not False

    def _current_fields(self) -> dict:
        f: dict = {}
        f["network_enabled"] = not self.var_no_net.get()
        f["guest_additions"] = self.var_guest_additions.get()
        f["full_screen"] = self.var_full_screen.get()
        self.share.collect(f)
        self.custom.collect(f)
        return f

    def _persist(self) -> None:
        if self._restoring or self._device_dir is None:
            return
        persist_subset(self._device_dir, self._baseline, PERSIST_KEYS,
                       self._current_fields())
        self._saved_state_warning.maybe_warn(self._device_dir)

    def _on_guest_additions_changed(self) -> None:
        self.refresh_resolution_state()
        self._persist()

    def collect_args(self, device: DeviceBundle) -> Optional[List[str]]:
        argv: List[str] = ["--device={}".format(device.name)]
        if self.var_log_all.get():
            argv.append("--log=ALL")
        if self.var_no_net.get():
            argv.append("--disable-network")
        if self.var_full_screen.get():
            argv.append("--full-screen")
        guest_additions = self.var_guest_additions.get()
        if guest_additions:
            argv.append("--guest-additions")
            key = self.custom.color_scheme_key()
            if key:
                argv.append("--ga-color-scheme={}".format(key))
        if self._guest_additions_locked:
            return argv
        if guest_additions or board_configurable_screen(device.meta.board_id):
            size = self.custom.resolution()
            if size is None:
                return None
            argv += ["--screen-width={}".format(size[0]),
                     "--screen-height={}".format(size[1])]
            bpp = self.custom.bpp_value()
            if bpp is not None:
                argv.append("--screen-bpp={}".format(bpp))
        if guest_additions and self.custom.dpi_enabled():
            dpi = self.custom.dpi_value_or_error()
            if dpi is None:
                return None
            argv.append("--screen-dpi={}".format(dpi))
        if guest_additions and self.custom.font_size_enabled():
            font_size = self.custom.font_size_value_or_error()
            if font_size is None:
                return None
            argv.append("--ga-font-size={}".format(font_size))
        return argv

    def _set_block_visible(self, visible: bool, *widgets: tk.Widget) -> None:
        for w in widgets:
            if visible:
                w.grid()
            else:
                w.grid_remove()

    def refresh_resolution_state(self) -> None:
        device = self._device
        locked = self._guest_additions_locked
        guest_additions = self.var_guest_additions.get() and not locked

        self._set_block_visible(self._guest_additions_available and not locked,
                                self.guest_block, self.guest_sep)

        self._set_block_visible(guest_additions, self.share.frame,
                                self.share_sep)
        self.share.refresh_state(self._locked)

        resolution_available = not locked and (
            device is not None
            and board_configurable_screen(device.meta.board_id))
        self.custom.refresh_state(guest_additions, resolution_available,
                                  self._color_scheme_available, self._locked)
        self._set_block_visible(guest_additions or resolution_available,
                                self.custom.frame, self.custom_sep)
