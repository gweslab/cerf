from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from board_database import ROM_TYPES, STORAGE_TYPES, BoardDatabaseError
from cerf_user_json import (ROM_BLOCK, STORAGE_BLOCK, read_board_id,
                            read_device_files, resolve_device_file,
                            storage_default_file)

PICKER_EXISTING_OR_POINT = "existing_or_point"
_STORAGE_PICKERS = (PICKER_EXISTING_OR_POINT,)

FileKey = Tuple[str, str]


@dataclass(frozen=True)
class DeviceFileType:
    section: str
    id: str
    name: str
    formats: Tuple[str, ...]
    note: str
    picker_type: str
    optional_for_storage_ids: Tuple[str, ...]

    @property
    def key(self) -> FileKey:
        return (self.section, self.id)

    @property
    def is_storage(self) -> bool:
        return self.section == STORAGE_BLOCK

    def default_value(self) -> str:
        return storage_default_file(self.id) if self.is_storage else ""


def _strings(row: dict, key: str) -> Tuple[str, ...]:
    value = row.get(key)
    if not isinstance(value, list):
        return ()
    return tuple(v for v in value if isinstance(v, str) and v)


def _text(row: dict, key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) else ""


def _rows_for_board(rows: List[dict], board_id: str) -> List[dict]:
    ids: List[str] = []
    for row in rows:
        if row["id"] not in ids:
            ids.append(row["id"])
    picked: List[dict] = []
    for type_id in ids:
        candidates = [r for r in rows if r["id"] == type_id]
        match = next((r for r in candidates
                      if board_id in _strings(r, "board_ids")), None)
        if match is None:
            match = next((r for r in candidates
                          if not _strings(r, "board_ids")), None)
        if match is not None:
            picked.append(match)
    return picked


def _file_type(section: str, row: dict) -> DeviceFileType:
    picker = _text(row, "picker_type")
    if section == STORAGE_BLOCK:
        picker = picker or PICKER_EXISTING_OR_POINT
        if picker not in _STORAGE_PICKERS:
            raise BoardDatabaseError(
                "storage_types '{}' has picker_type '{}', which this launcher "
                "does not support".format(row["id"], picker))
    return DeviceFileType(
        section=section, id=row["id"], name=_text(row, "name") or row["id"],
        formats=_strings(row, "formats"), note=_text(row, "note"),
        picker_type=picker,
        optional_for_storage_ids=_strings(row, "optional_for_storage_ids"))


def _check_storage_rows() -> None:
    for row in STORAGE_TYPES:
        _file_type(STORAGE_BLOCK, row)


_check_storage_rows()


def device_file_types(board_id: str) -> List[DeviceFileType]:
    return ([_file_type(ROM_BLOCK, r) for r in _rows_for_board(ROM_TYPES, board_id)]
            + [_file_type(STORAGE_BLOCK, r)
               for r in _rows_for_board(STORAGE_TYPES, board_id)])


def storage_files(device_dir: Path) -> List[Path]:
    _, storage = read_device_files(device_dir)
    values = dict(storage)
    for ftype in device_file_types(read_board_id(device_dir)):
        if ftype.is_storage:
            values.setdefault(ftype.id, ftype.default_value())
    return [resolve_device_file(v, device_dir) for v in values.values()]


def _file_non_empty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def is_required(ftype: DeviceFileType, values: Dict[FileKey, str],
                base_dir: Optional[Path]) -> bool:
    if ftype.is_storage:
        return False
    for storage_id in ftype.optional_for_storage_ids:
        value = (values.get((STORAGE_BLOCK, storage_id), "")
                 or storage_default_file(storage_id))
        path = resolve_device_file(value, base_dir)
        if path.is_absolute() and _file_non_empty(path):
            return False
    return True


def file_problem(ftype: DeviceFileType, values: Dict[FileKey, str],
                 base_dir: Optional[Path]) -> Optional[str]:
    value = values.get(ftype.key, "")
    if not value:
        if is_required(ftype, values, base_dir):
            return "Pick the {}.".format(ftype.name)
        return None
    path = resolve_device_file(value, base_dir)
    if not ftype.is_storage:
        if not path.is_file():
            return "{} not found:\n{}".format(ftype.name, path)
        return None
    if not path.is_absolute():
        if Path(value).parent != Path("."):
            return "The folder for the {} does not exist:\n{}".format(
                ftype.name, Path(value).parent)
        return None
    if path.is_dir():
        return "{} must be a file, not a folder:\n{}".format(ftype.name, path)
    if not path.parent.is_dir():
        return "The folder for the {} does not exist:\n{}".format(
            ftype.name, path.parent)
    return None
