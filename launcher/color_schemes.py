from __future__ import annotations

from board_database import OPERATING_SYSTEMS


def _os_name(os_id: str) -> str:
    entry = OPERATING_SYSTEMS.get(os_id)
    return entry.get("name", os_id) if entry else os_id

COLOR_SCHEMES = [
    ("",              "Default"),
    ("ce2_grayscale", "Windows CE 2.0 Grayscale"),
    ("hpc3",          _os_name("handheld_pc_pro")),
    ("hpc2000",       _os_name("handheld_pc_2000")),
    ("ce4",           _os_name("windows_ce_net")),
    ("win2k",         "Windows 2000"),
    ("xp",            "Windows XP Luna"),
    ("vista",         "Windows Vista"),
    ("wm5",           _os_name("windows_mobile_5")),
    ("wm6",           _os_name("windows_mobile_6")),
    ("wm6_green",     "Windows Mobile 6 Green"),
    ("wm6_guava",     "Windows Mobile 6 Guava Bubbles"),
    ("wm65",          "Windows Mobile 6.5"),
]
COLOR_SCHEME_KEYS = [k for (k, _d) in COLOR_SCHEMES]
_KEY_TO_LABEL = {k: d for (k, d) in COLOR_SCHEMES}


def color_scheme_label(key: str) -> str:
    return _KEY_TO_LABEL.get(key, key)
