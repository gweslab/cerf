from __future__ import annotations
from i18n import t
from database_text import field_text

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Union

from branded_dialog import scaled
from choice_combo import ChoiceCombo
from cpu_config import (AUTO, CUSTOM_LABEL, TYPE_BOOLEAN, TYPE_ENUM, TYPE_HEX,
                        auto_preset_label, board_arch, board_defaults,
                        matching_preset, param_value_label, params_for_arch,
                        parse_text, preset_name, presets_for_arch,
                        resolve_preset, value_label)
from emulation_speed import CPU_RATE_KEY, CPU_RATE_PRESETS
from launch_options_multiplier import MultiplierOptionBlock
from rich_text import plain
from settings_card import CONTROL_GAP_DIP, SettingsColumn, SettingsGroup, SettingsRow
from ui_dialogs import show_error

PAGE_CPU_CONFIG = "cpu_config"
WARNING = 'launcher.properties_page_cpu.tweaking_these_settings_will_render_emulation_broken'

PresetChoice = Union[str, int, None]


class _ChoiceParam:
    def __init__(self, row: SettingsRow, param: dict, default: object,
                 on_change: Callable[[], None]) -> None:
        self.param = param
        self._default = default
        self.combo = ChoiceCombo(row.frame, on_change=on_change)
        row.control(self.combo.widget)
        if param.get("type") == TYPE_BOOLEAN:
            options: List[object] = [True, False]
        else:
            options = [o.get("id") for o in param.get("enum_values", [])]
        self.combo.configure([AUTO] + options, self._label)

    def _label(self, value: object) -> str:
        if value == AUTO:
            return param_value_label(self.param, self._default, None)
        return value_label(self.param, value)

    def get(self) -> Optional[object]:
        value = self.combo.get()
        return None if value == AUTO else value

    def set(self, value: Optional[object]) -> None:
        self.combo.set(AUTO if value is None else value)

    def commit(self) -> bool:
        return True

    def set_enabled(self, enabled: bool) -> None:
        self.combo.set_enabled(enabled)


class _TextParam:
    def __init__(self, row: SettingsRow, param: dict, default: object,
                 on_change: Callable[[], None]) -> None:
        self.param = param
        self._default = default
        self._override: Optional[object] = None
        self._on_change = on_change
        frame = ttk.Frame(row.frame)
        frame.columnconfigure(0, weight=1)
        self.var = tk.StringVar()
        self.entry = ttk.Entry(frame, textvariable=self.var, width=1)
        self.entry.grid(row=0, column=0, sticky="ew")
        self.reset = ttk.Button(frame, text=t("common.reset"), command=self._on_reset)
        self.reset.grid(row=0, column=1,
                        padx=(scaled(frame, CONTROL_GAP_DIP) // 2, 0))
        row.control(frame)
        self.entry.bind("<FocusIn>", self._on_focus_in)
        self.entry.bind("<FocusOut>", lambda _e: self.commit())
        self.entry.bind("<Return>", lambda _e: self.commit())
        self._show()

    def _show(self) -> None:
        self.var.set(param_value_label(self.param, self._default, self._override))
        self.entry.config(style="Hint.TEntry" if self._override is None
                          else "TEntry")

    def _on_focus_in(self, _event: object) -> None:
        if self._override is None:
            self.var.set(value_label(self.param, self._default))
            self.entry.config(style="TEntry")
            self.entry.select_range(0, "end")

    def _on_reset(self) -> None:
        self.set(None)
        self._on_change()

    def get(self) -> Optional[object]:
        return self._override

    def set(self, value: Optional[object]) -> None:
        self._override = value
        self._show()

    def commit(self) -> bool:
        text = self.var.get().strip()
        if text == param_value_label(self.param, self._default, self._override):
            return True
        if self._override is None and text == value_label(self.param, self._default):
            self._show()
            return True
        value = parse_text(self.param, text)
        if value is None:
            return False
        self.set(value)
        self._on_change()
        return True

    def invalid_message(self) -> str:
        if self.param.get("type") == TYPE_HEX:
            return t('launcher.properties_page_cpu.enter_a_hexadecimal_value_such_as_0x1f', value=field_text("cpu_config_params", self.param))
        return t('launcher.properties_page_cpu.enter_a_whole_number_for_value', value=field_text("cpu_config_params", self.param))

    def set_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.entry.config(state=state)
        self.reset.config(state=state)


ParamRow = Union[_ChoiceParam, _TextParam]


class CpuConfigPage:
    key = PAGE_CPU_CONFIG
    title = "properties.cpu"

    def __init__(self, parent: tk.Misc, window: tk.Misc,
                 bind_wheel: Callable[[tk.Misc], None]) -> None:
        self._window = window
        self._bind_wheel = bind_wheel
        self._enabled = True
        self._board_id: Optional[str] = None
        self._arch: Optional[str] = None
        self._defaults: Dict[str, object] = {}
        self._presets: List[dict] = []
        self._rows: List[ParamRow] = []
        self._group: Optional[SettingsGroup] = None

        page = SettingsColumn(parent)
        self.frame = page.frame
        page.group().note(t(WARNING))
        self.rate = MultiplierOptionBlock(
            page.group().row(t("launcher.properties_page_cpu.cpu_rate_multiplier"), [
                plain(t("launcher.properties_page_cpu.multiply_the_guest_cpu_clock_the_guest_does_more"))]),
            CPU_RATE_KEY, CPU_RATE_PRESETS)
        self._holder = page.column().frame
        self.set_board("")

    def set_board(self, board_id: str) -> None:
        if board_id == self._board_id:
            return
        self._board_id = board_id
        self._arch = board_arch(board_id)
        self._defaults = board_defaults(board_id)
        self._presets = presets_for_arch(self._arch)
        self._build_rows()

    def _build_rows(self) -> None:
        if self._group is not None:
            self._group.frame.destroy()
        self._group = SettingsGroup(self._holder)
        self._group.frame.grid(row=0, column=0, sticky="ew")
        self._holder.columnconfigure(0, weight=1)
        row = self._group.row(t("launcher.config_preview.preset"))
        self.preset = ChoiceCombo(row.frame, on_change=self._on_preset)
        row.control(self.preset.widget)
        self.preset.configure([AUTO] + list(range(len(self._presets))),
                              self._preset_label)
        self._rows = []
        for param in params_for_arch(self._arch):
            row = self._group.row(field_text("cpu_config_params", param))
            default = self._defaults.get(param["id"])
            if param.get("type") in (TYPE_BOOLEAN, TYPE_ENUM):
                self._rows.append(_ChoiceParam(row, param, default,
                                               self._sync_preset))
            else:
                self._rows.append(_TextParam(row, param, default,
                                             self._sync_preset))
        self._sync_preset()
        self.set_enabled(self._enabled)
        self._bind_wheel(self._group.frame)

    def _preset_label(self, value: PresetChoice) -> str:
        if value == AUTO:
            return auto_preset_label(self._board_id)
        if isinstance(value, int):
            return preset_name(self._presets[value])
        return t(CUSTOM_LABEL)

    def _overrides(self) -> Dict[str, object]:
        out: Dict[str, object] = {}
        for row in self._rows:
            value = row.get()
            if value is not None:
                out[row.param["id"]] = value
        return out

    def _sync_preset(self) -> None:
        overrides = self._overrides()
        if not overrides:
            self.preset.set(AUTO)
            return
        values = dict(self._defaults)
        values.update(overrides)
        match = matching_preset(self._arch, values)
        self.preset.set(self._presets.index(match) if match else None)

    def _on_preset(self) -> None:
        choice = self.preset.get()
        if choice == AUTO:
            for row in self._rows:
                row.set(None)
        elif isinstance(choice, int):
            values = resolve_preset(self._presets[choice])
            for row in self._rows:
                row.set(values.get(row.param["id"]))
        self._sync_preset()

    def load(self, model: dict) -> None:
        self.set_board(model.get("board_id", ""))
        overrides = model.get("cpu_config")
        overrides = overrides if isinstance(overrides, dict) else {}
        for row in self._rows:
            row.set(overrides.get(row.param["id"]))
        self._sync_preset()
        self.rate.load(model)

    def store(self, model: dict) -> None:
        model["cpu_config"] = self._overrides()
        self.rate.store(model)

    def validate(self) -> bool:
        for row in self._rows:
            if row.commit():
                continue
            show_error(self._window, t("launcher.properties_page_cpu.invalid_value"), row.invalid_message())
            row.entry.focus_set()
            return False
        return True

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.preset.set_enabled(enabled)
        self.rate.set_enabled(enabled)
        for row in self._rows:
            row.set_enabled(enabled)
