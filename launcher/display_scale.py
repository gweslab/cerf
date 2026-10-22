from __future__ import annotations

import re
from functools import lru_cache
from typing import List, Tuple

from app_paths import INTEGER_SCALES_HEADER, read_source_header

SCALE_DYNAMIC = 0
SCALE_ORIGINAL = 1

_INTEGER_SCALES = re.compile(r"kIntegerScales\[\]\s*=\s*\{([^}]*)\}")


@lru_cache(maxsize=None)
def _integer_scales() -> Tuple[int, ...]:
    match = _INTEGER_SCALES.search(read_source_header(INTEGER_SCALES_HEADER))
    if match is None:
        raise ValueError("{} has no kIntegerScales table".format(INTEGER_SCALES_HEADER[0]))
    return tuple(int(value) for value in match.group(1).split(","))


def scale_choices() -> List[int]:
    return [SCALE_DYNAMIC, SCALE_ORIGINAL] + list(_integer_scales())


def scale_label(value: int) -> str:
    if value == SCALE_DYNAMIC:
        return "Dynamic"
    if value == SCALE_ORIGINAL:
        return "Original view"
    return "Integer scale {}x".format(value)
