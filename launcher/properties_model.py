from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple

from board_info import board_configurable_screen, board_features
from cerf_user_json import (read_board_id, read_device_meta, read_rom_primary,
                            write_board_rom_overrides, write_user_meta_name)
from device_state import DeviceBundle
from persisted_options import (PERSIST_KEYS, auto_resolution,
                               effective_values, persist_subset)

GA_KEYS = ("share_folder", "width", "height", "bpp", "dpi", "font_size",
           "color_scheme")
RESET_NEEDING_KEYS = ("bpp", "dpi", "font_size", "color_scheme")


@dataclass
class PropertiesSubject:
    device_dir: Path
    display_name: str
    os_ver_major: int
    os_name: str
    forbid_guest_additions: bool
    default_width: Optional[int]
    default_height: Optional[int]

    @staticmethod
    def of_bundle(devices_dir: Path, device: DeviceBundle) -> "PropertiesSubject":
        return PropertiesSubject(
            device_dir=devices_dir / device.name,
            display_name=(device.meta.name or device.meta.device_name
                          or device.name),
            os_ver_major=device.meta.os_ver_major,
            os_name=device.meta.os_name,
            forbid_guest_additions=device.meta.forbid_guest_additions,
            default_width=device.default_screen_width,
            default_height=device.default_screen_height)

    @staticmethod
    def of_device_dir(device_dir: Path) -> "PropertiesSubject":
        meta, width, height = read_device_meta(device_dir)
        return PropertiesSubject(
            device_dir=device_dir,
            display_name=meta.name or meta.device_name or device_dir.name,
            os_ver_major=meta.os_ver_major,
            os_name=meta.os_name,
            forbid_guest_additions=meta.forbid_guest_additions,
            default_width=width,
            default_height=height)

    def guest_additions_available(self, board_id: str) -> bool:
        if self.forbid_guest_additions or self.os_ver_major == 1:
            return False
        return board_features(board_id).get("guest_additions") is not False

    def display_page_available(self, model: dict) -> bool:
        board_id = model.get("board_id", "")
        ga_on = (model.get("guest_additions", False)
                 and self.guest_additions_available(board_id))
        return board_configurable_screen(board_id) and not ga_on

    def auto_size(self, board_id: str) -> Tuple[int, int]:
        return auto_resolution(self.default_width, self.default_height,
                               board_id)


class PropertiesModel:
    def __init__(self, subject: PropertiesSubject, verbose_logs: bool) -> None:
        self.subject = subject
        self._baseline, eff = effective_values(subject.device_dir)
        self.values = dict(eff)
        self.values["board_id"] = read_board_id(subject.device_dir)
        self.values["rom_primary"] = read_rom_primary(subject.device_dir)
        self.values["name"] = subject.display_name
        self.values["verbose_logs"] = verbose_logs
        self.initial = dict(self.values)

    def reset_needing_changed(self) -> bool:
        return any(self.values.get(k) != self.initial.get(k)
                   for k in RESET_NEEDING_KEYS)

    def save(self, owned_keys: Iterable[str], board_rom: bool) -> None:
        values = dict(self.values)
        if not self.subject.guest_additions_available(values["board_id"]):
            values["guest_additions"] = False
        device_dir = self.subject.device_dir
        if board_rom:
            write_board_rom_overrides(device_dir, values["board_id"],
                                      values["rom_primary"])
            if values["name"] != self.initial["name"]:
                write_user_meta_name(device_dir, values["name"])
        persist_subset(device_dir, self._baseline, owned_keys, values)

    def save_all(self) -> None:
        self.save(PERSIST_KEYS, board_rom=True)

    def save_live(self) -> None:
        self.save(GA_KEYS, board_rom=False)
