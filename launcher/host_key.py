from __future__ import annotations

import ctypes
from typing import List, Sequence

from app_settings import remove_key, write_key
from bundle_repositories import config_path, load_config

HOST_KEY_KEY = "host_key"

VK_CANCEL = 0x03
VK_ESCAPE = 0x1B
VK_PRIOR = 0x21
VK_NEXT = 0x22
VK_END = 0x23
VK_HOME = 0x24
VK_LEFT = 0x25
VK_UP = 0x26
VK_RIGHT = 0x27
VK_DOWN = 0x28
VK_SNAPSHOT = 0x2C
VK_INSERT = 0x2D
VK_DELETE = 0x2E
VK_LWIN = 0x5B
VK_RWIN = 0x5C
VK_APPS = 0x5D
VK_DIVIDE = 0x6F
VK_LSHIFT = 0xA0
VK_RSHIFT = 0xA1
VK_LCONTROL = 0xA2
VK_RCONTROL = 0xA3
VK_LMENU = 0xA4
VK_RMENU = 0xA5

DEFAULT_HOST_KEY = (VK_RCONTROL,)
MAX_HOST_KEY_LEN = 8

UNREACHABLE_VKS = frozenset((0x01, 0x02, 0x04, 0x05, 0x06, 0x10, 0x11, 0x12))

_MAPVK_VK_TO_VSC = 0
_EXTENDED_KEY_LPARAM_BIT = 1 << 24

# Microsoft, Keyboard Input Overview, "Extended-Key Flag":
# https://learn.microsoft.com/en-us/windows/win32/inputdev/about-keyboard-input
_EXTENDED_VKS = frozenset((
    VK_RMENU, VK_RCONTROL, VK_INSERT, VK_DELETE, VK_HOME, VK_END,
    VK_PRIOR, VK_NEXT, VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN,
    VK_CANCEL, VK_SNAPSHOT, VK_DIVIDE, VK_LWIN, VK_RWIN, VK_APPS,
))

_KEYSYM_VK = {
    "Control_L": VK_LCONTROL, "Control_R": VK_RCONTROL,
    "Shift_L": VK_LSHIFT, "Shift_R": VK_RSHIFT,
    "Alt_L": VK_LMENU, "Alt_R": VK_RMENU,
    "Meta_L": VK_LMENU, "Meta_R": VK_RMENU,
    "Super_L": VK_LWIN, "Super_R": VK_RWIN,
    "Win_L": VK_LWIN, "Win_R": VK_RWIN,
    "Menu": VK_APPS, "App": VK_APPS,
}


def vk_label(vk: int) -> str:
    try:
        user32 = ctypes.windll.user32
        scan_code = user32.MapVirtualKeyW(vk, _MAPVK_VK_TO_VSC)
        if scan_code:
            lparam = scan_code << 16
            if vk in _EXTENDED_VKS:
                lparam |= _EXTENDED_KEY_LPARAM_BIT
            buf = ctypes.create_unicode_buffer(64)
            if user32.GetKeyNameTextW(lparam, buf, 64) > 0:
                name = buf.value
                if name and name[0] >= " ":
                    return name
    except (AttributeError, OSError):
        pass
    return "VK 0x%02X" % vk


def combo_label(vks: Sequence[int]) -> str:
    return "+".join(vk_label(vk) for vk in vks) if vks else combo_label(
        DEFAULT_HOST_KEY)


def vk_from_tk_event(event) -> int:
    vk = _KEYSYM_VK.get(getattr(event, "keysym", ""))
    if vk:
        return vk
    code = getattr(event, "keycode", 0)
    return code if isinstance(code, int) and 1 <= code <= 255 else 0


def normalize(raw) -> List[int]:
    if isinstance(raw, bool):
        return list(DEFAULT_HOST_KEY)
    if isinstance(raw, int):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return list(DEFAULT_HOST_KEY)
    out: List[int] = []
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, int):
            continue
        if item < 1 or item > 255 or item in out:
            continue
        if item in UNREACHABLE_VKS:
            continue
        out.append(item)
        if len(out) == MAX_HOST_KEY_LEN:
            break
    return out or list(DEFAULT_HOST_KEY)


def read_host_key() -> List[int]:
    return normalize(load_config(config_path()).get(HOST_KEY_KEY))


def write_host_key(vks: Sequence[int]) -> None:
    normalized = normalize(list(vks))
    if normalized == list(DEFAULT_HOST_KEY):
        remove_key(HOST_KEY_KEY)
    else:
        write_key(HOST_KEY_KEY, normalized)
