from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from cerf_user_json import read_persist_fields, write_persist_overrides
from launch_options_presets import (DEFAULT_SCREEN_WIDTH,
                                    DEFAULT_SCREEN_HEIGHT)


PERSIST_KEYS = ("network_enabled", "guest_additions", "color_scheme",
                "full_screen", "width", "height", "dpi", "font_size", "bpp",
                "share_folder")


def resolve_baseline(base: dict, default_width: Optional[int],
                     default_height: Optional[int]) -> dict:
    b = {}
    b["network_enabled"] = base.get("network_enabled", True)
    b["guest_additions"] = base.get("guest_additions", False)
    b["color_scheme"] = base.get("color_scheme", "")
    b["full_screen"] = base.get("full_screen", False)
    if "share_folder" in base:
        b["share_folder"] = base["share_folder"]
    if "width" in base:
        b["width"] = base["width"]
    elif default_width:
        b["width"] = default_width
    else:
        b["width"] = DEFAULT_SCREEN_WIDTH
    if "height" in base:
        b["height"] = base["height"]
    elif default_height:
        b["height"] = default_height
    else:
        b["height"] = DEFAULT_SCREEN_HEIGHT
    if "dpi" in base:
        b["dpi"] = base["dpi"]
    if "font_size" in base:
        b["font_size"] = base["font_size"]
    if "bpp" in base:
        b["bpp"] = base["bpp"]
    return b


def effective_values(device_dir: Optional[Path],
                     default_width: Optional[int],
                     default_height: Optional[int]) -> tuple:
    base = {}
    override = {}
    if device_dir is not None:
        base, override = read_persist_fields(device_dir)
    baseline = resolve_baseline(base, default_width, default_height)
    eff = dict(baseline)
    eff.update(override)
    return baseline, eff


def persist_subset(device_dir: Path, baseline: dict,
                   owned_keys: Iterable[str], current: dict) -> None:
    _base, override = read_persist_fields(device_dir)
    merged = dict(override)
    for key in owned_keys:
        merged.pop(key, None)
        if key in current and current[key] != baseline.get(key):
            merged[key] = current[key]
    write_persist_overrides(device_dir, merged)
