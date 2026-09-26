"""Resolution of on-disk locations: the exe directory, the devices tree,
cerf.exe, the app icon, the feature-icon assets, and the CERF version."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple


LAUNCHER_DIR_NAME = "launcher"


def exe_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def install_root() -> Path:
    if getattr(sys, "frozen", False):
        return exe_dir().parent
    return exe_dir()


def resolve_devices_dir() -> Path:
    return install_root() / "devices"


def resolve_cerf_exe() -> Optional[Path]:
    candidate = install_root() / "cerf.exe"
    if candidate.is_file():
        return candidate
    return None


def resolve_icon(name: str = "cerf.ico") -> Optional[Path]:
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = Path(meipass) / name
        if candidate.is_file():
            return candidate
    candidate = exe_dir() / name
    if candidate.is_file():
        return candidate
    repo_candidate = exe_dir() / ".." / "cerf" / "assets" / name
    if repo_candidate.is_file():
        return repo_candidate.resolve()
    return None


def resolve_icons_dir() -> Optional[Path]:
    meipass = getattr(sys, "_MEIPASS", None)
    candidates: List[Path] = []
    if meipass:
        candidates.append(Path(meipass) / "assets" / "icons")
    candidates.append(exe_dir() / "assets" / "icons")
    candidates.append(Path(__file__).resolve().parent / "assets" / "icons")
    for path in candidates:
        if path.is_dir():
            return path
    return None


def resolve_asset(name: str) -> Optional[Path]:
    meipass = getattr(sys, "_MEIPASS", None)
    candidates: List[Path] = []
    if meipass:
        candidates.append(Path(meipass) / "assets" / name)
    candidates.append(exe_dir() / "assets" / name)
    here = Path(__file__).resolve().parent
    candidates.append(here / "assets" / name)
    candidates.append(here.parent / "cerf" / "assets" / name)
    for path in candidates:
        if path.is_file():
            return path
    return None


def _version_header_text() -> str:
    meipass = getattr(sys, "_MEIPASS", None)
    candidates: List[Path] = []
    if meipass:
        candidates.append(Path(meipass) / "version.h")
    candidates.append(exe_dir() / "version.h")
    candidates.append(exe_dir() / ".." / "cerf" / "version.h")
    for path in candidates:
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="ignore")
    return ""


def _int_define(text: str, name: str) -> Optional[int]:
    match = re.search(r"#define\s+" + name + r"\s+(\d+)", text)
    return int(match.group(1)) if match else None


def _str_define(text: str, name: str) -> str:
    match = re.search(r'#define\s+' + name + r'\s+"([^"]*)"', text)
    return match.group(1) if match else ""


def resolve_version_tuple() -> Optional[tuple]:
    text = _version_header_text()
    major = _int_define(text, "CERF_VERSION_MAJOR")
    minor = _int_define(text, "CERF_VERSION_MINOR")
    if major is None or minor is None:
        return None
    return (major, minor,
            _int_define(text, "CERF_VERSION_PATCH") or 0,
            _int_define(text, "CERF_VERSION_BUILD") or 0)


def resolve_version_parts() -> Tuple[str, str]:
    text = _version_header_text()
    major = _int_define(text, "CERF_VERSION_MAJOR")
    minor = _int_define(text, "CERF_VERSION_MINOR")
    if major is None or minor is None:
        return "", ""
    patch = _int_define(text, "CERF_VERSION_PATCH") or 0
    version = "{}.{}".format(major, minor)
    if patch:
        version += ".{}".format(patch)
    build = _int_define(text, "CERF_VERSION_BUILD") or 0
    if not build:
        return version, ""
    detail = [part for part in ("build {}".format(build),
                                _str_define(text, "CERF_VERSION_DATE"),
                                _str_define(text, "CERF_VERSION_SHA")) if part]
    return version, ", ".join(detail)


def resolve_version() -> str:
    version, detail = resolve_version_parts()
    if not version or not detail:
        return version
    return "{} ({})".format(version, detail)
