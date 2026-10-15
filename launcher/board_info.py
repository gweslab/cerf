from __future__ import annotations
from i18n import t, data_text
from database_text import record_key

from typing import List, Optional, Tuple

from board_database import BOARDS, board, family_of, soc_family_of, soc_of, sort_text

SUPPORT_BOOTABLE_FULL = "bootable_full"
SUPPORT_BOOTABLE_PARTIAL = "bootable_partial"
SUPPORT_UNKNOWN_PARTIAL = "unknown_partial"
SUPPORT_NO_SUPPORT = "no_support"

RUNNING_LEVELS = (SUPPORT_BOOTABLE_FULL, SUPPORT_BOOTABLE_PARTIAL)

SUPPORT_LABELS = {
    SUPPORT_BOOTABLE_FULL: "board.support.bootable_full",
    SUPPORT_BOOTABLE_PARTIAL: "board.support.bootable_partial",
    SUPPORT_UNKNOWN_PARTIAL: "board.support.unknown_partial",
    SUPPORT_NO_SUPPORT: "board.support.no_support",
}


def support_label(level: str) -> str:
    key = SUPPORT_LABELS.get(level)
    return t(key) if key else ""

WARN = "warn"
DANGER = "danger"

_WARNING_SEVERITIES = {
    SUPPORT_BOOTABLE_PARTIAL: WARN,
    SUPPORT_UNKNOWN_PARTIAL: WARN,
    SUPPORT_NO_SUPPORT: DANGER,
}


def board_sort_key(board_name: object) -> tuple[int, str]:
    name = sort_text(board_name)
    if not name:
        tier = 0
    elif name.startswith("device emulator"):
        tier = 2
    else:
        tier = 1
    return (tier, name)


def board_support_level(board_id: str) -> Optional[str]:
    entry = board(board_id)
    if entry is None:
        return None
    level = entry.get("support_level")
    return level if isinstance(level, str) else None


def board_runs(board_id: str) -> bool:
    return board_support_level(board_id) in RUNNING_LEVELS


def board_support_warning(board_id: str) -> Optional[Tuple[str, str]]:
    if not board_id:
        return None
    if board(board_id) is None:
        return (DANGER, t("board.support.unknown_board"))
    level = board_support_level(board_id) or ""
    severity = _WARNING_SEVERITIES.get(level)
    return (severity, support_label(level)) if severity else None


def board_extra_notes(board_id: str) -> List[str]:
    entry = board(board_id)
    if entry is None:
        return []
    notes = entry.get("notes")
    if not isinstance(notes, list):
        return []
    family = family_of(board_id) or {}
    inherited = family.get("notes", [])
    inherited = inherited if isinstance(inherited, list) else []
    result = []
    for index, note in enumerate(notes):
        if not isinstance(note, str) or not note.strip():
            continue
        if index < len(inherited):
            key = record_key("board_families", family) + ".notes." + str(index)
        else:
            key = record_key("boards", entry) + ".notes." + str(index - len(inherited))
        result.append(data_text(key, note))
    return result


def board_soc_cpu(board_id: str) -> Optional[str]:
    family = soc_family_of(board_id)
    if family is None:
        return None
    arch = family.get("arch")
    return arch if isinstance(arch, str) else None


def board_display_name(board_id: str) -> str:
    entry = board(board_id)
    if entry is None:
        return ""
    name = entry.get("name")
    return name if isinstance(name, str) else ""


def board_family_name(board_id: str) -> str:
    family = family_of(board_id)
    if family is None:
        return ""
    name = family.get("name")
    return name if isinstance(name, str) else ""


def board_device_year(board_id: str) -> int:
    entry = board(board_id)
    year = entry.get("device_year") if entry else None
    if isinstance(year, int) and not isinstance(year, bool) and year > 0:
        return year
    return 0


def board_soc_label(board_id: str) -> str:
    soc = soc_of(board_id)
    family = soc_family_of(board_id)
    if soc is None or family is None:
        return ""
    return "{} ({})".format(soc.get("name", ""), family.get("name", ""))


def board_configurable_screen(board_id: str) -> bool:
    entry = board(board_id)
    return bool(entry.get("configurable_screen", False)) if entry else False


DEFAULT_GA_COLOR_DEPTH = 24


def board_ga_color_depth(board_id: str) -> int:
    entry = board(board_id)
    depth = entry.get("ga_color_depth") if entry else None
    if isinstance(depth, int) and not isinstance(depth, bool) and depth > 0:
        return depth
    return DEFAULT_GA_COLOR_DEPTH


def board_panel_size(board_id: str) -> Optional[tuple]:
    entry = board(board_id)
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


def all_boards() -> List[dict]:
    return list(BOARDS)


def running_boards() -> List[dict]:
    return [b for b in BOARDS if b.get("support_level") in RUNNING_LEVELS]


def board_features(board_id: str) -> dict:
    entry = board(board_id)
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
