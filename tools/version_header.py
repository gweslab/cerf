from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from header_defines import int_define, replace_define, str_define

VERSION_H = Path(__file__).resolve().parent.parent / "cerf-qt" / "version.h"
RELEASE_PARTS = ("major", "minor", "patch")


def _define(field: str) -> str:
    return "CERF_VERSION_" + field.upper()


def read_int(field: str) -> int:
    return int_define(VERSION_H, _define(field))


def read_str(field: str) -> str:
    return str_define(VERSION_H, _define(field))


def release_numbers() -> List[int]:
    return [read_int(part) for part in RELEASE_PARTS]


def rewrite(bodies: Dict[str, str]) -> None:
    text = VERSION_H.read_text(encoding="utf-8")
    for field, body in bodies.items():
        text = replace_define(text, _define(field), body)
    VERSION_H.write_bytes(text.encode("utf-8"))
