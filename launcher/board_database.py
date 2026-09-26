from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from app_paths import install_root

DB_FILENAME = "db.json"


def _db_path() -> Optional[Path]:
    candidates = [install_root() / DB_FILENAME,
                  Path(__file__).resolve().parent.parent / "bundled" / DB_FILENAME]
    for path in candidates:
        if path.is_file():
            return path
    return None


class BoardDatabaseError(RuntimeError):
    pass


def _load() -> dict:
    path = _db_path()
    if path is None:
        return {}
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            text = f.read()
    except OSError as exc:
        raise BoardDatabaseError("{} is unreadable: {}".format(path, exc))
    if not text.strip():
        return {}
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BoardDatabaseError("{} is unreadable: {}".format(path, exc))
    if not isinstance(obj, dict):
        raise BoardDatabaseError(
            "{} must hold a JSON object at the top level".format(path))
    return obj


def _rows(table: str) -> List[dict]:
    rows = _DB.get(table)
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)]


def _by_id(table: str) -> Dict[str, dict]:
    return {r["id"]: r for r in _rows(table)}


_DB = _load()

OPERATING_SYSTEMS = _by_id("operating_systems")
SOC_FAMILIES = _by_id("soc_families")
SOCS = _by_id("socs")
DEVICE_FEATURES = _rows("device_features")
DEVICES = _rows("devices")
DEVICES_BY_ID = _by_id("devices")
ROM_TYPES = _rows("rom_types")
STORAGE_TYPES = _rows("storage_types")

FEATURE_SPECS = [(f["id"], f.get("icon", f["id"]), f.get("name", f["id"]))
                 for f in DEVICE_FEATURES]


def sort_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.casefold().split())


def device(board_id: object) -> Optional[dict]:
    if not isinstance(board_id, str):
        return None
    return DEVICES_BY_ID.get(board_id.strip())


def soc_of(board_id: object) -> Optional[dict]:
    entry = device(board_id)
    return SOCS.get(entry.get("soc_id", "")) if entry else None


def soc_family_of(board_id: object) -> Optional[dict]:
    soc = soc_of(board_id)
    return SOC_FAMILIES.get(soc.get("family_id", "")) if soc else None


def operating_systems_of(board_id: object) -> List[dict]:
    entry = device(board_id)
    if entry is None:
        return []
    ids = entry.get("operating_system_ids")
    if not isinstance(ids, list):
        return []
    return [OPERATING_SYSTEMS[i] for i in ids if i in OPERATING_SYSTEMS]
