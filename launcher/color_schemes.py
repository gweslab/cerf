from __future__ import annotations
from i18n import t

COLOR_SCHEMES = [
    ("",              "Default"),
    ("ce2_grayscale", "Windows CE 2.0 Grayscale"),
    ("hpc3",          "Handheld PC 3.0 Professional"),
    ("hpc2000",       "Handheld PC 2000"),
    ("ce4",           "Windows CE .NET"),
    ("win2k",         "Windows 2000"),
    ("xp",            "Windows XP Luna"),
    ("vista",         "Windows Vista"),
    ("wm5",           "Windows Mobile 5"),
    ("wm6",           "Windows Mobile 6"),
    ("wm6_green",     "Windows Mobile 6 Green"),
    ("wm6_guava",     "Windows Mobile 6 Guava Bubbles"),
    ("wm65",          "Windows Mobile 6.5"),
]
COLOR_SCHEME_KEYS = [k for (k, _d) in COLOR_SCHEMES]
_KEY_TO_LABEL = {k: d for (k, d) in COLOR_SCHEMES}


def color_scheme_label(key: str) -> str:
    if key in ("", "ce2_grayscale", "wm6_green", "wm6_guava"):
        return t("colors." + (key or "default"))
    return _KEY_TO_LABEL.get(key, key)
