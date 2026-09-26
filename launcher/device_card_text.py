from __future__ import annotations

from typing import List, Tuple

from board_info import board_soc_label
from device_model import _os_name_has_version, _table_device_label
from device_state import DeviceBundle, format_size

SEP = "  ·  "


def os_title(d: DeviceBundle) -> str:
    meta = d.meta
    edition = (meta.os_name or "").strip() or _table_device_label(d)
    lang = (meta.os_language or "").strip()
    return f"{edition}{SEP}{lang}" if lang else edition


def os_ce_version(d: DeviceBundle) -> str:
    meta = d.meta
    major = meta.os_ver_major or 0
    minor = meta.os_ver_minor or 0
    if not (major or minor):
        return ""
    if _os_name_has_version(meta.os_name or "", major, minor):
        return ""
    ver = f"CE {major}.{minor}"
    if meta.os_ver_build:
        ver += f".{meta.os_ver_build}"
    return ver


def card_title(d: DeviceBundle, collide: bool) -> str:
    if d.meta.name:
        return d.meta.name
    title = os_title(d)
    if collide:
        ce = os_ce_version(d)
        if ce:
            title = f"{title}{SEP}{ce}"
    return title


def card_heading(d: DeviceBundle, collide: bool) -> str:
    title = card_title(d, collide)
    notes = SEP.join(n.strip() for n in d.meta.os_notes if n and n.strip())
    return f"{title}{SEP}{notes}" if notes else title


def card_detail_parts(d: DeviceBundle, include_ce: bool) -> Tuple[str, str, str]:
    parts: List[str] = []
    if include_ce:
        ce = os_ce_version(d)
        if ce:
            parts.append(ce)
    if d.meta.os_year:
        parts.append(str(d.meta.os_year))
    soc = board_soc_label(d.meta.board_id)
    size = (format_size(d.remote.unpacked_size) if d.remote
            else format_size(d.rom_size))
    prefix = SEP.join(parts)
    if soc:
        if prefix:
            prefix += SEP
        suffix = (SEP + size) if size else ""
    else:
        if size:
            prefix = (prefix + SEP + size) if prefix else size
        suffix = ""
    return prefix, soc, suffix
