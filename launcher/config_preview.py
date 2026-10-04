from __future__ import annotations

import tkinter as tk
from pathlib import PureWindowsPath
from tkinter import ttk
from typing import Callable, List, Tuple

from board_info import board_display_name, board_ga_color_depth
from color_schemes import color_scheme_label
from device_file_types import device_file_types
from launch_options_bpp import bpp_label, model_bpp
from launch_options_dpi import dpi_label, model_dpi
from launch_options_font_size import font_size_label, model_font_size
from properties_model import PropertiesModel
from properties_page_board import BoardRomPage, PAGE_BOARD
from properties_page_display import DisplayPage, PAGE_DISPLAY
from properties_page_emulator import EmulatorSettingsPage, PAGE_EMULATOR
from properties_page_ga import (GuestAdditionsPage, PAGE_GUEST_ADDITIONS,
                                cleartype_label, model_cleartype)
from resolution_block import model_size, resolution_label
from share_folder_block import MOUNT_PREFIX
from side_block import SideBlock

Rows = List[Tuple[str, str]]


def _on_off(value: bool) -> str:
    return "On" if value else "Off"


class ConfigPreviewPanel:
    def __init__(self, inner: ttk.Frame, first_row: int,
                 on_open: Callable[[str], None],
                 bind_wheel: Callable[[tk.Misc], None]) -> None:
        self._bind_wheel = bind_wheel
        self._wrap = 220

        def block(title: str, row: int, page: str) -> SideBlock:
            b = SideBlock(inner, title, row=first_row + row,
                          on_click=lambda: on_open(page))
            b.body.columnconfigure(1, weight=1)
            return b

        self.board = block(BoardRomPage.title, 0, PAGE_BOARD)
        self.ga = block(GuestAdditionsPage.title, 1, PAGE_GUEST_ADDITIONS)
        self.display = block(DisplayPage.title, 2, PAGE_DISPLAY)
        self.emulator = block(EmulatorSettingsPage.title, 3, PAGE_EMULATOR)
        self._blocks = [self.board, self.ga, self.display, self.emulator]
        self.clear()

    def set_wraplength(self, wrap: int) -> None:
        self._wrap = wrap

    def retheme(self) -> None:
        for b in self._blocks:
            b.retheme()

    def clear(self) -> None:
        for b in self._blocks:
            b.grid_remove()

    def show(self, model: PropertiesModel) -> None:
        subject = model.subject
        values = model.values
        board_id = values.get("board_id", "")
        auto_size = subject.auto_size(board_id)

        board_rows: Rows = [
            ("Board", board_display_name(board_id) or board_id or "-")]
        for ftype in device_file_types(board_id):
            value = (values.get(ftype.section, {}).get(ftype.id, "")
                     or ftype.default_value())
            board_rows.append((ftype.name,
                               PureWindowsPath(value).name if value else "-"))
        self._fill(self.board, board_rows)

        if subject.guest_additions_available(board_id):
            self._fill(self.ga, self._ga_rows(values, auto_size,
                                              board_ga_color_depth(board_id)))
        else:
            self.ga.grid_remove()

        if subject.display_page_available(values):
            self._fill(self.display, [
                ("Resolution",
                 resolution_label(model_size(values), auto_size)),
                ("Color depth", bpp_label(model_bpp(values), None))])
        else:
            self.display.grid_remove()

        self._fill(self.emulator, [
            ("Borderless full screen", _on_off(values.get("full_screen",
                                                          False))),
            ("Internet connection",
             "Attached" if values.get("network_enabled", True)
             else "Detached"),
            ("Verbose logs", _on_off(values.get("verbose_logs", False)))])

    def _ga_rows(self, values: dict, auto_size: Tuple[int, int],
                 auto_depth: int) -> Rows:
        if not values.get("guest_additions", False):
            return [("Status", "Disabled")]
        share = values.get("share_folder")
        rows: Rows = [("Status", "Enabled"),
                      ("Shared folder", share or "None")]
        if share:
            rows.append(("Mount point",
                         MOUNT_PREFIX + values.get("mount_point", "")))
        rows += [("Resolution",
                  resolution_label(model_size(values), auto_size)),
                 ("Color depth", bpp_label(model_bpp(values), auto_depth)),
                 ("DPI", dpi_label(model_dpi(values))),
                 ("Font size", font_size_label(model_font_size(values))),
                 ("ClearType", cleartype_label(model_cleartype(values))),
                 ("Color scheme",
                  color_scheme_label(values.get("color_scheme", "")))]
        return rows

    def _fill(self, block: SideBlock, rows: Rows) -> None:
        for child in block.body.winfo_children():
            child.destroy()
        for r, (label, value) in enumerate(rows):
            ttk.Label(block.body, text=label).grid(row=r, column=0,
                                                   sticky="nw", padx=(0, 12))
            ttk.Label(block.body, text=value, style="Hint.TLabel",
                      wraplength=max(80, self._wrap // 2),
                      justify="left").grid(row=r, column=1, sticky="nw")
        block.grid()
        self._bind_wheel(block.body)
