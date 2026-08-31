"""cerf-user.json access: the per-device file for user edits that win over
the launcher/remote-authored cerf.json - persisted launch options, the
display-name override (meta.name), and the launcher's bundle-repository link
block."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from device_state import _load_json_object, _str_or_empty, write_cerf_json

CERF_USER_JSON_FILENAME = "cerf-user.json"
LAUNCHER_LINK_KEY = "launcher"


@dataclass(frozen=True)
class LauncherLink:
    """cerf-user.json {"launcher": {...}}: which remote repository bundle this
    device directory was installed from - the update/link identity."""

    repository_url: str
    name_on_repository: str


def update_user_json(device_dir: Path, mutate) -> None:
    """Read-modify-write cerf-user.json: `mutate(obj)` edits the parsed object
    in place; keys it does not touch survive. An empty result removes the
    file."""
    path = device_dir / CERF_USER_JSON_FILENAME
    obj = _load_json_object(path) or {}
    mutate(obj)
    if not obj:
        try:
            path.unlink()
        except OSError:
            pass
        return
    write_cerf_json(path, obj)


def read_launcher_link(device_dir: Path) -> Optional[LauncherLink]:
    obj = _load_json_object(device_dir / CERF_USER_JSON_FILENAME)
    if obj is None:
        return None
    block = obj.get(LAUNCHER_LINK_KEY)
    if not isinstance(block, dict):
        return None
    url = block.get("repository_url")
    name = block.get("name_on_repository")
    if not isinstance(url, str) or not url:
        return None
    if not isinstance(name, str) or not name:
        return None
    return LauncherLink(repository_url=url, name_on_repository=name)


def write_launcher_link(device_dir: Path, link: LauncherLink) -> None:
    def mutate(obj: dict) -> None:
        obj[LAUNCHER_LINK_KEY] = {
            "repository_url": link.repository_url,
            "name_on_repository": link.name_on_repository,
        }
    update_user_json(device_dir, mutate)


def read_user_meta_name(device_dir: Path) -> str:
    obj = _load_json_object(device_dir / CERF_USER_JSON_FILENAME)
    if obj is None:
        return ""
    m = obj.get("meta")
    if not isinstance(m, dict):
        return ""
    return _str_or_empty(m.get("name"))


def write_user_meta_name(device_dir: Path, name: str) -> None:
    """Set (or, with an empty name, drop) the user's display-name override."""
    def mutate(obj: dict) -> None:
        meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
        if name:
            meta["name"] = name
        else:
            meta.pop("name", None)
        if meta:
            obj["meta"] = meta
        else:
            obj.pop("meta", None)
    update_user_json(device_dir, mutate)


def read_rom_primary(device_dir: Path) -> str:
    """rom.primary with the cerf-user.json override applied; "" when neither
    file names one."""
    primary = ""
    for name in ("cerf.json", CERF_USER_JSON_FILENAME):
        obj = _load_json_object(device_dir / name)
        if obj is None:
            continue
        rom = obj.get("rom")
        if isinstance(rom, dict):
            v = rom.get("primary")
            if isinstance(v, str) and v:
                primary = v
    return primary


def _extract_persist_fields(obj) -> dict:
    out: dict = {}
    if not isinstance(obj, dict):
        return out
    net = obj.get("network")
    if isinstance(net, dict) and isinstance(net.get("enabled"), bool):
        out["network_enabled"] = net["enabled"]
    ga = obj.get("guest_additions")
    if isinstance(ga, bool):
        out["guest_additions"] = ga
    elif isinstance(ga, dict):
        if isinstance(ga.get("enabled"), bool):
            out["guest_additions"] = ga["enabled"]
        cs = ga.get("override_color_scheme")
        if isinstance(cs, str) and cs:
            out["color_scheme"] = cs
        fs = ga.get("override_font_size")
        if isinstance(fs, int) and not isinstance(fs, bool):
            out["font_size"] = fs
    if isinstance(obj.get("full_screen"), bool):
        out["full_screen"] = obj["full_screen"]
    sf = obj.get("share_folder")
    if isinstance(sf, str) and sf:
        out["share_folder"] = sf
    board = obj.get("board")
    if isinstance(board, dict):
        w = board.get("configurable_screen_width")
        h = board.get("configurable_screen_height")
        d = board.get("configurable_screen_dpi")
        b = board.get("configurable_screen_bpp")
        if isinstance(w, int) and w > 0:
            out["width"] = w
        if isinstance(h, int) and h > 0:
            out["height"] = h
        if isinstance(d, int) and d > 0:
            out["dpi"] = d
        if isinstance(b, int) and b > 0:
            out["bpp"] = b
    return out


def read_persist_fields(device_dir: Path) -> tuple[dict, dict]:
    base = _extract_persist_fields(_load_json_object(device_dir / "cerf.json"))
    override = _extract_persist_fields(
        _load_json_object(device_dir / CERF_USER_JSON_FILENAME))
    return base, override


_PERSIST_BOARD_KEYS = {
    "width": "configurable_screen_width",
    "height": "configurable_screen_height",
    "dpi": "configurable_screen_dpi",
    "bpp": "configurable_screen_bpp",
}


def write_persist_overrides(device_dir: Path, fields: dict) -> None:
    """Replace the persisted launch-option overrides with `fields`, leaving
    every other cerf-user.json key (meta, launcher link, ...) untouched."""
    def mutate(obj: dict) -> None:
        net = obj.get("network") if isinstance(obj.get("network"), dict) else {}
        if "network_enabled" in fields:
            net["enabled"] = fields["network_enabled"]
        else:
            net.pop("enabled", None)
        if net:
            obj["network"] = net
        else:
            obj.pop("network", None)
        cs = fields.get("color_scheme")
        fs = fields.get("font_size")
        if cs or fs is not None:
            ga_obj: dict = {}
            if "guest_additions" in fields:
                ga_obj["enabled"] = fields["guest_additions"]
            if cs:
                ga_obj["override_color_scheme"] = cs
            if fs is not None:
                ga_obj["override_font_size"] = fs
            obj["guest_additions"] = ga_obj
        elif "guest_additions" in fields:
            obj["guest_additions"] = fields["guest_additions"]
        else:
            obj.pop("guest_additions", None)
        if "full_screen" in fields:
            obj["full_screen"] = fields["full_screen"]
        else:
            obj.pop("full_screen", None)
        if fields.get("share_folder"):
            obj["share_folder"] = fields["share_folder"]
        else:
            obj.pop("share_folder", None)
        board = obj.get("board") if isinstance(obj.get("board"), dict) else {}
        for field, json_key in _PERSIST_BOARD_KEYS.items():
            if field in fields:
                board[json_key] = fields[field]
            else:
                board.pop(json_key, None)
        if board:
            obj["board"] = board
        else:
            obj.pop("board", None)
    update_user_json(device_dir, mutate)
