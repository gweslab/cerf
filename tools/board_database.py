from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from header_defines import str_define

_ROOT = Path(os.path.abspath(__file__)).parent.parent
DB_PATH = _ROOT / "libCerfCore" / "db.json"
_SUPPORT_LEVEL_TEXT = _ROOT / "libCerfCore" / "include" / "cerfcore" / "core" / "support_level_text.h"
_BOARD_ORDER_TEXT = _ROOT / "cerf-qt" / "cerfman" / "board_order_text.h"

RUNNING_LEVELS = tuple(str_define(_SUPPORT_LEVEL_TEXT, "CERF_RUNNING_SUPPORT_LEVELS").split())
_LAST_TIER_PREFIX = str_define(_BOARD_ORDER_TEXT, "CERF_LAST_BOARD_TIER_PREFIX")


class BoardDatabaseError(RuntimeError):
    pass


def _load() -> dict:
    try:
        obj = json.loads(DB_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise BoardDatabaseError("{} is unreadable: {}".format(DB_PATH, exc))
    if not isinstance(obj, dict):
        raise BoardDatabaseError("{} must hold a JSON object at the top level".format(DB_PATH))
    return obj


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
    return out


_DB = _load()

SOC_FAMILIES = _by_id("soc_families")
SOCS = _by_id("socs")
BOARD_FAMILIES_BY_ID = _by_id("board_families")
BOARDS = [_effective_board(b) for b in _rows("boards")]
BOARDS_BY_ID = {b["id"]: b for b in BOARDS}
GENERIC_PARTS: List[dict] = _rows("device_generic_parts")
BOARD_CONFIG_PARAMS = _by_id("board_config_params")


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
