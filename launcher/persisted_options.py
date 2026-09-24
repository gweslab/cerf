from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Tuple

from board_info import board_panel_size
from cerf_user_json import read_persist_fields, write_persist_overrides
from launch_options_presets import (DEFAULT_SCREEN_WIDTH,
                                    DEFAULT_SCREEN_HEIGHT)


PERSIST_KEYS = ("network_enabled", "guest_additions", "color_scheme",
                "full_screen", "width", "height", "dpi", "font_size", "bpp",
                "share_folder")

EXPLICIT_KEYS = ("width", "height", "bpp")


def auto_resolution(default_width: Optional[int],
                    default_height: Optional[int],
                    board_id: object) -> Tuple[int, int]:
    panel = board_panel_size(board_id)
    width = default_width or (panel[0] if panel else DEFAULT_SCREEN_WIDTH)
    height = default_height or (panel[1] if panel else DEFAULT_SCREEN_HEIGHT)
    return width, height


def resolve_baseline(base: dict) -> dict:
    b = {}
    b["network_enabled"] = base.get("network_enabled", True)
    b["guest_additions"] = base.get("guest_additions", False)
    b["color_scheme"] = base.get("color_scheme", "")
    b["full_screen"] = base.get("full_screen", False)
    for key in ("share_folder", "dpi", "font_size"):
        if key in base:
            b[key] = base[key]
    return b


def effective_values(device_dir: Optional[Path]) -> tuple:
    base = {}
    override = {}
    if device_dir is not None:
        base, override = read_persist_fields(device_dir)
    baseline = resolve_baseline(base)
    eff = dict(baseline)
    eff.update(override)
    return baseline, eff


def persist_subset(device_dir: Path, baseline: dict,
                   owned_keys: Iterable[str], current: dict) -> None:
    _base, override = read_persist_fields(device_dir)
    merged = dict(override)
    for key in owned_keys:
        merged.pop(key, None)
        if key not in current:
            continue
        if key in EXPLICIT_KEYS or current[key] != baseline.get(key):
            merged[key] = current[key]
    write_persist_overrides(device_dir, merged)
