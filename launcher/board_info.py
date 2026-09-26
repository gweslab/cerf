from __future__ import annotations

from typing import List, Optional

from board_database import DEVICES, device, soc_family_of, soc_of, sort_text


def board_sort_key(board_name: object) -> tuple[int, str]:
    board = sort_text(board_name)
    if not board:
        tier = 0
    elif board == "device emulator":
        tier = 2
    else:
        tier = 1
    return (tier, board)


def board_support_state(board_id: str) -> Optional[bool]:
    entry = device(board_id)
    if entry is None:
        return None
    return bool(entry.get("supported", False))


def board_extra_notes(board_id: str) -> List[str]:
    entry = device(board_id)
    if entry is None:
        return []
    notes = entry.get("notes")
    if not isinstance(notes, list):
        return []
    return [n for n in notes if isinstance(n, str) and n.strip()]


def board_soc_cpu(board_id: str) -> Optional[str]:
    family = soc_family_of(board_id)
    if family is None:
        return None
    arch = family.get("arch")
    return arch if isinstance(arch, str) else None


def board_display_name(board_id: str) -> str:
    entry = device(board_id)
    if entry is None:
        return ""
    name = entry.get("name")
    return name if isinstance(name, str) else ""


def board_soc_label(board_id: str) -> str:
    soc = soc_of(board_id)
    family = soc_family_of(board_id)
    if soc is None or family is None:
        return ""
    return "{} ({})".format(soc.get("name", ""), family.get("name", ""))


def board_configurable_screen(board_id: str) -> bool:
    entry = device(board_id)
    return bool(entry.get("configurable_screen", False)) if entry else False


def board_panel_size(board_id: str) -> Optional[tuple]:
    entry = device(board_id)
    if entry is None:
        return None
    panel = entry.get("lcd_panel_size")
    if not isinstance(panel, dict):
        return None
    width = panel.get("width")
    height = panel.get("height")
    if not isinstance(width, int) or not isinstance(height, int):
        return None
    if width < 1 or height < 1:
        return None
    return (width, height)


def supported_boards() -> List[dict]:
    return [e for e in DEVICES if e.get("supported") is True]


def board_features(board_id: str) -> dict:
    entry = device(board_id)
    if entry is None:
        return {}
    features = entry.get("device_features")
    if not isinstance(features, list):
        return {}
    out = {}
    for f in features:
        if isinstance(f, dict) and isinstance(f.get("feature_id"), str):
            out[f["feature_id"]] = bool(f.get("supported"))
    return out
