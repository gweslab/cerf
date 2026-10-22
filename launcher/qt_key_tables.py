from __future__ import annotations

import re
import sys
from functools import lru_cache
from typing import Dict, List, Tuple

from app_paths import (EVDEV_VK_HEADER, HOST_KEY_NAMES_HEADER, MAC_KEY_VK_HEADER,
                       read_source_header)

_HEX = re.compile(r"0x[0-9A-Fa-f]+")
_SIDED = re.compile(r"\{\s*(\d+)\s*,\s*(0x[0-9A-Fa-f]+)\s*\}")
_HEX_PAIR = re.compile(r"\{\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*\}")
_NAME = re.compile(r'\{\s*(0x[0-9A-Fa-f]+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}')
_TK_AQUA_VIRTUAL_SHIFT = 24


def _block(text: str, symbol: str) -> str:
    start = text.index(symbol)
    open_brace = text.index("{", text.index("=", start))
    return text[open_brace + 1:text.index("\n};", open_brace)]


@lru_cache(maxsize=None)
def _x_position_tables() -> Tuple[int, List[int], Dict[int, int]]:
    text = read_source_header(EVDEV_VK_HEADER)
    offset = int(re.search(r"kXKeycodeEvdevOffset\s*=\s*(\d+)", text).group(1))
    evdev_to_vk = [int(v, 16) for v in _HEX.findall(_block(text, "kEvdevToVk["))]
    sided = {int(code): int(vk, 16)
             for code, vk in _SIDED.findall(_block(text, "kEvdevSidedVks[]"))}
    return offset, evdev_to_vk, sided


@lru_cache(maxsize=None)
def _mac_position_tables() -> Tuple[List[int], Dict[int, int]]:
    text = read_source_header(MAC_KEY_VK_HEADER)
    key_to_vk = [int(v, 16) for v in _HEX.findall(_block(text, "kMacKeyToVk["))]
    sided = {int(code, 16): int(vk, 16)
             for code, vk in _HEX_PAIR.findall(_block(text, "kMacKeySidedVks[]"))}
    return key_to_vk, sided


def _names(text: str, symbol: str) -> Dict[int, str]:
    return {int(vk, 16): re.sub(r"\\(.)", r"\1", name)
            for vk, name in _NAME.findall(_block(text, symbol))}


@lru_cache(maxsize=None)
def key_names() -> Dict[int, str]:
    text = read_source_header(HOST_KEY_NAMES_HEADER)
    names = _names(text, "kHostKeyNames[]")
    if sys.platform == "darwin":
        names.update(_names(text, "kHostKeyNamesMacos[]"))
    return names


def vk_from_x_keycode(keycode: int) -> int:
    offset, evdev_to_vk, sided = _x_position_tables()
    evdev = keycode - offset
    if evdev < 0 or evdev >= len(evdev_to_vk):
        return 0
    vk = evdev_to_vk[evdev]
    return sided.get(evdev, vk) if vk else 0


def vk_from_tk_aqua_keycode(keycode: int) -> int:
    key_to_vk, sided = _mac_position_tables()
    virtual = (keycode >> _TK_AQUA_VIRTUAL_SHIFT) & 0xFF
    if virtual >= len(key_to_vk):
        return 0
    vk = key_to_vk[virtual]
    return sided.get(virtual, vk) if vk else 0
