from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from header_defines import str_define

_ROOT = Path(os.path.abspath(__file__)).parent.parent
DB_ROOT = _ROOT / "libCerfCore" / "db"
sys.path.insert(0, str(_ROOT / "libCerfCore" / "sad"))

from sad import SadError, compile_tree
_SUPPORT_LEVEL_TEXT = _ROOT / "libCerfCore" / "include" / "cerfcore" / "core" / "support_level_text.h"
_BOARD_ORDER_TEXT = _ROOT / "cerf-qt" / "cerfman" / "board_order_text.h"

RUNNING_LEVELS = tuple(str_define(_SUPPORT_LEVEL_TEXT, "CERF_RUNNING_SUPPORT_LEVELS").split())
_LAST_TIER_PREFIX = str_define(_BOARD_ORDER_TEXT, "CERF_LAST_BOARD_TIER_PREFIX")


class BoardDatabaseError(RuntimeError):
    pass


def _load() -> dict:
    try:
        return compile_tree(DB_ROOT, "json")
    except (OSError, SadError) as exc:
        raise BoardDatabaseError("{} does not compile: {}".format(DB_ROOT, exc))


def _rows(table: str) -> List[dict]:
    rows = _DB.get(table)
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)]


def _by_id(table: str) -> Dict[str, dict]:
    return {r["id"]: r for r in _rows(table)}


def _list(row: dict, key: str) -> list:
    value = row.get(key)
    return value if isinstance(value, list) else []


def _connects(part: dict, board_row: dict) -> bool:
    family_id = board_row.get("board_family_id")
    return any(board_row["id"] in _list(c, "board_ids") or family_id in _list(c, "board_family_ids")
               for c in _list(part, "connections") if isinstance(c, dict))


def _effective_board(board_row: dict) -> dict:
    family = BOARD_FAMILIES_BY_ID.get(board_row.get("board_family_id", ""), {})
    out = {k: v for k, v in family.items() if k not in ("id", "name")}
    out.update(board_row)
    out["notes"] = _list(family, "notes") + _list(board_row, "notes")
    out["device_specs"] = [s for row in (family, board_row) for s in _list(row, "device_specs")
                           if isinstance(s, dict) and isinstance(s.get("generic_part_id"), str)]
    config: Dict[str, dict] = {}
    for row in (family, board_row):
        if isinstance(row.get("board_config"), dict):
            for param, setting in row["board_config"].items():
                config[param] = {**config.get(param, {}), **setting}
    if config:
        out["board_config"] = config
    parts = [p for p in PARTS if _connects(p, board_row)]
    parts += [PARTS_BY_ID[s["default"]] for param, s in config.items()
              if BOARD_CONFIG_PARAMS[param].get("part_picker") and s.get("default") in PARTS_BY_ID]
    order = {g["id"]: i for i, g in enumerate(GENERIC_PARTS)}
    out["parts"] = sorted(parts, key=lambda p: (order[p["generic_part_id"]], PARTS.index(p)))
    return out


_DB = _load()

SOC_FAMILIES = _by_id("soc_families")
SOCS = _by_id("socs")
BOARD_FAMILIES_BY_ID = _by_id("board_families")
GENERIC_PARTS: List[dict] = _rows("device_generic_parts")
GENERIC_PARTS_BY_ID = {g["id"]: g for g in GENERIC_PARTS}
PARTS: List[dict] = _rows("parts")
PARTS_BY_ID = {p["id"]: p for p in PARTS}
BOARD_CONFIG_PARAMS = _by_id("board_config_params")
BOARDS = [_effective_board(b) for b in _rows("boards")]
BOARDS_BY_ID = {b["id"]: b for b in BOARDS}


def part_label(part: dict) -> str:
    generic = GENERIC_PARTS_BY_ID[part["generic_part_id"]]["name"]
    name = part.get("name", "")
    if not part.get("unknown_name"):
        label = name
    else:
        label = f"{generic} {name}" if name else generic
    if "chip_count" in part:
        label = f"{part['chip_count']}x {label}"
    if "width" in part and "height" in part:
        return f"{label} ({part['width']}x{part['height']})"
    if "size_mb" in part:
        return f"{label} ({part['size_mb']} MB)"
    return label


def sort_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.casefold().split())


def board_sort_key(board_name: object) -> Tuple[int, str]:
    name = sort_text(board_name)
    if not name:
        tier = 0
    elif name.startswith(_LAST_TIER_PREFIX):
        tier = 2
    else:
        tier = 1
    return (tier, name)


def soc_of(board_id: str) -> Optional[dict]:
    entry = BOARDS_BY_ID.get(board_id)
    return SOCS.get(entry.get("soc_id", "")) if entry else None


def soc_family_of(board_id: str) -> Optional[dict]:
    soc = soc_of(board_id)
    return SOC_FAMILIES.get(soc.get("family_id", "")) if soc else None


def running_boards() -> List[dict]:
    return [b for b in BOARDS if b.get("support_level") in RUNNING_LEVELS]
