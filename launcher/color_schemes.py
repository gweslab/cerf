"""Guest-additions color-scheme override catalog: the (key, label) choices the
launch-options dropdown offers, chronological by era, and the key<->label maps.
The key is what cerf.exe receives as --ga-color-scheme."""
from __future__ import annotations

from board_database import OPERATING_SYSTEMS


def _os_name(os_id: str) -> str:
    entry = OPERATING_SYSTEMS.get(os_id)
    return entry.get("name", os_id) if entry else os_id

COLOR_SCHEMES = [
    ("",              "Do not override color scheme"),
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
CS_KEY_TO_LABEL = {k: d for (k, d) in COLOR_SCHEMES}
CS_LABEL_TO_KEY = {d: k for (k, d) in COLOR_SCHEMES}
