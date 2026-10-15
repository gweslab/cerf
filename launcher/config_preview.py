from __future__ import annotations
from i18n import t

import tkinter as tk
import tkinter.font as tkfont
from pathlib import PureWindowsPath
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Set, Tuple

from board_info import board_display_name, board_ga_color_depth
from board_support_label import apply_support_warning
from color_schemes import color_scheme_label
from device_file_types import device_file_types
from database_text import field_text
from emulation_speed import (CPU_RATE_KEY, THROTTLE_KEY, model_choice,
                             multiplier_label)
from launch_options_bpp import bpp_label, model_bpp
from launch_options_dpi import dpi_label, model_dpi
from launch_options_font_size import font_size_label, model_font_size
import cpu_config
from properties_model import PropertiesModel
from properties_page_board import BoardRomPage, PAGE_BOARD
from properties_page_cpu import CpuConfigPage, PAGE_CPU_CONFIG
from properties_page_display import DisplayPage, PAGE_DISPLAY
from properties_page_emulator import EmulatorSettingsPage, PAGE_EMULATOR
from properties_page_ga import (GuestAdditionsPage, PAGE_GUEST_ADDITIONS,
                                cleartype_label, model_cleartype)
from key_value_rows import KeyValueRows
from resolution_block import model_size, resolution_label
from share_folder_block import MOUNT_PREFIX
from side_block import SideBlock, chevron_reserve

Rows = List[Tuple[str, str]]
WIDTH_DEFAULT = 220
WARNING_ROW = 1000
WARNING_GAP = 6


def _on_off(value: bool) -> str:
    return t("launcher.config_preview.on") if value else t("common.off")


class ConfigPreviewPanel:
    def __init__(self, inner: ttk.Frame, first_row: int,
                 on_open: Callable[[str], None],
                 bind_wheel: Callable[[tk.Misc], None]) -> None:
        self._bind_wheel = bind_wheel
        self._reserve = chevron_reserve(inner)
        self._width = WIDTH_DEFAULT
        self._font = tkfont.nametofont(str(ttk.Style(inner).lookup("TLabel", "font")))

        def block(title: str, row: int, page: str) -> SideBlock:
            return SideBlock(inner, title, row=first_row + row,
                             on_click=lambda: on_open(page))

        self.board = block(t(BoardRomPage.title), 0, PAGE_BOARD)
        self.ga = block(t(GuestAdditionsPage.title), 1, PAGE_GUEST_ADDITIONS)
        self.display = block(t(DisplayPage.title), 2, PAGE_DISPLAY)
        self.cpu = block(t(CpuConfigPage.title), 3, PAGE_CPU_CONFIG)
        self.emulator = block(t(EmulatorSettingsPage.title), 4, PAGE_EMULATOR)
        self._blocks = [self.board, self.ga, self.display, self.cpu,
                        self.emulator]
        self._rows: Dict[SideBlock, KeyValueRows] = {
            b: KeyValueRows(b.body) for b in self._blocks}
        self._shown: Set[SideBlock] = set()
        self._board_warning: Optional[ttk.Label] = None
        self.clear()

    def set_wraplength(self, wrap: int) -> None:
        width = max(1, wrap - self._reserve)
        if width != self._width:
            self._width = width
            self._arrange()

    def retheme(self) -> None:
        for b in self._blocks:
            b.retheme()

    def clear(self) -> None:
        for b in self._blocks:
            self._hide(b)

    def _hide(self, block: SideBlock) -> None:
        block.grid_remove()
        self._shown.discard(block)

    def _arrange(self) -> None:
        shown = [self._rows[b] for b in self._blocks if b in self._shown]
        stacked = not all(r.fits(self._font, self._width) for r in shown)
        for rows in shown:
            rows.arrange(self._width, stacked)
        if self._board_warning is not None:
            self._board_warning.config(wraplength=self._width)

    def show(self, model: PropertiesModel) -> None:
        subject = model.subject
        values = model.values
        board_id = values.get("board_id", "")
        auto_size = subject.auto_size(board_id)

        board_rows: Rows = [
            (t("common.board"), board_display_name(board_id) or board_id or "-")]
        for ftype in device_file_types(board_id):
            value = (values.get(ftype.section, {}).get(ftype.id, "")
                     or ftype.default_value())
            board_rows.append((ftype.name,
                               PureWindowsPath(value).name if value else "-"))
        self._fill(self.board, board_rows)
        self._show_board_warning(board_id)

        if subject.guest_additions_available(board_id):
            self._fill(self.ga, self._ga_rows(values, auto_size,
                                              board_ga_color_depth(board_id)))
        else:
            self._hide(self.ga)

        if subject.display_page_available(values):
            self._fill(self.display, [
                (t("common.resolution"),
                 resolution_label(model_size(values), auto_size)),
                (t("common.color_depth"), bpp_label(model_bpp(values), None))])
        else:
            self._hide(self.display)

        if cpu_config.available(board_id):
            self._fill(self.cpu,
                       [(t("launcher.properties_page_cpu.cpu_rate_multiplier"),
                         multiplier_label(model_choice(values, CPU_RATE_KEY)))] +
                       self._cpu_rows(board_id, values.get("cpu_config")))
        else:
            self._hide(self.cpu)

        self._fill(self.emulator, [
            (t("launcher.properties_page_emulator.throttle_multiplier"),
             multiplier_label(model_choice(values, THROTTLE_KEY))),
            (t("launcher.config_preview.borderless_full_screen"), _on_off(values.get("full_screen",
                                                          False))),
            (t("common.internet_connection"),
             t("common.attached") if values.get("network_enabled", True)
             else t("common.detached")),
            (t("launcher.config_preview.verbose_logs"), _on_off(values.get("verbose_logs", False)))])
        self._arrange()

    def _show_board_warning(self, board_id: str) -> None:
        label = ttk.Label(self.board.body, justify="left",
                          wraplength=self._width)
        if not apply_support_warning(label, board_id):
            label.destroy()
            self._board_warning = None
            return
        label.grid(row=WARNING_ROW, column=0, columnspan=2, sticky="w",
                   pady=(WARNING_GAP, 0))
        self._board_warning = label
        self.board.adopt_children()
        self._bind_wheel(self.board.body)

    def _ga_rows(self, values: dict, auto_size: Tuple[int, int],
                 auto_depth: int) -> Rows:
        if not values.get("guest_additions", False):
            return [(t("launcher.config_preview.status"), t("common.disabled"))]
        share = values.get("share_folder")
        rows: Rows = [(t("launcher.config_preview.status"), t("common.enabled")),
                      (t("common.shared_folder"), share or t("common.none"))]
        if share:
            rows.append((t("common.mount_point"),
                         MOUNT_PREFIX + values.get("mount_point", "")))
        size = model_size(values)
        if size is not None:
            rows.append((t("common.resolution"), resolution_label(size, auto_size)))
        bpp = model_bpp(values)
        if bpp is not None:
            rows.append((t("common.color_depth"), bpp_label(bpp, auto_depth)))
        dpi = model_dpi(values)
        if dpi is not None:
            rows.append(("DPI", dpi_label(dpi)))
        font_size = model_font_size(values)
        if font_size is not None:
            rows.append((t("launcher.config_preview.font_size"), font_size_label(font_size)))
        cleartype = model_cleartype(values)
        if cleartype is not None:
            rows.append(("ClearType", cleartype_label(cleartype)))
        scheme = values.get("color_scheme", "")
        if scheme:
            rows.append((t("launcher.config_preview.color_scheme"), color_scheme_label(scheme)))
        return rows

    def _cpu_rows(self, board_id: str, overrides: object) -> Rows:
        overrides = cpu_config.applicable_overrides(board_id, overrides)
        rows: Rows = [(t("launcher.config_preview.preset"), cpu_config.preset_label(board_id, overrides))]
        for param in cpu_config.params_for_arch(cpu_config.board_arch(board_id)):
            if param["id"] in overrides:
                rows.append((field_text("cpu_config_params", param),
                             cpu_config.value_label(param,
                                                    overrides[param["id"]])))
        return rows

    def _fill(self, block: SideBlock, rows: Rows) -> None:
        self._rows[block].fill(rows)
        self._shown.add(block)
        block.grid()
        block.adopt_children()
        self._bind_wheel(block.body)
