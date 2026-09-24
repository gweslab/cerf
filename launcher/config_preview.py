from __future__ import annotations

import tkinter as tk
from pathlib import PureWindowsPath
from tkinter import ttk
from typing import Callable, List, Tuple

from board_info import board_display_name
from color_schemes import CS_KEY_TO_LABEL, color_scheme_supported_for_os
from properties_model import PropertiesModel
from properties_page_board import PAGE_BOARD
from properties_page_display import PAGE_DISPLAY
from properties_page_emulator import PAGE_EMULATOR
from properties_page_ga import PAGE_GUEST_ADDITIONS
from side_block import SideBlock

Rows = List[Tuple[str, str]]


def _on_off(value: bool) -> str:
    return "On" if value else "Off"


def _resolution_text(values: dict, auto_size: Tuple[int, int]) -> str:
    if "width" in values and "height" in values:
        return "{} × {}".format(values["width"], values["height"])
    return "Auto ({} × {})".format(*auto_size)


def _bpp_text(values: dict) -> str:
    bpp = values.get("bpp")
    return "{} bpp".format(bpp) if bpp else "Auto"


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

        self.board = block("Board/ROM", 0, PAGE_BOARD)
        self.ga = block("Guest Additions", 1, PAGE_GUEST_ADDITIONS)
        self.display = block("Display", 2, PAGE_DISPLAY)
        self.emulator = block("Emulator Settings", 3, PAGE_EMULATOR)
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

        rom = values.get("rom_primary", "")
        self._fill(self.board, [
            ("Board", board_display_name(board_id) or board_id or "-"),
            ("ROM", PureWindowsPath(rom).name if rom else "-")])

        if subject.guest_additions_available(board_id):
            self._fill(self.ga, self._ga_rows(subject, values, auto_size))
        else:
            self.ga.grid_remove()

        if subject.display_page_available(values):
            self._fill(self.display, [
                ("Resolution", _resolution_text(values, auto_size)),
                ("Color depth", _bpp_text(values))])
        else:
            self.display.grid_remove()

        self._fill(self.emulator, [
            ("Borderless full screen", _on_off(values.get("full_screen",
                                                          False))),
            ("Internet connection",
             "Attached" if values.get("network_enabled", True)
             else "Detached"),
            ("Verbose logs", _on_off(values.get("verbose_logs", False)))])

    def _ga_rows(self, subject, values: dict,
                 auto_size: Tuple[int, int]) -> Rows:
        if not values.get("guest_additions", False):
            return [("Status", "Disabled")]
        rows: Rows = [("Status", "Enabled"),
                      ("Shared folder", values.get("share_folder") or "None"),
                      ("Resolution", _resolution_text(values, auto_size)),
                      ("Color depth", _bpp_text(values)),
                      ("DPI", str(values["dpi"]) if "dpi" in values
                       else "Default"),
                      ("Font size", str(values["font_size"])
                       if "font_size" in values else "Default")]
        if color_scheme_supported_for_os(subject.os_name):
            key = values.get("color_scheme", "")
            rows.append(("Color scheme",
                         CS_KEY_TO_LABEL.get(key, "None") if key else "None"))
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
