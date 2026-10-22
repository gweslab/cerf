from __future__ import annotations

import json
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

KEY = "host_branch"
HOST_KEY_KEY = "host_key"
WIN32_X86 = "win32-x86"
LINUX_AMD64 = "linux-amd64"
MACOS_ARM64 = "macos-arm64"

VK_RMENU = 0xA5


@dataclass(frozen=True)
class HostBranch:
    name: str
    label: str
    platform_dir: str
    frontend: str
    launcher: str
    forwarder: Optional[str]
    builds_ce_apps: bool
    packed_artifact: bool
    cerf_json_defaults: Dict[str, object] = field(default_factory=dict)


_BRANCHES = {
    WIN32_X86: HostBranch(
        name=WIN32_X86, label="Windows", platform_dir="Win32",
        frontend="cerf.exe", launcher="launcher/launcher.exe", forwarder="launcher.exe",
        builds_ce_apps=True, packed_artifact=False),
    LINUX_AMD64: HostBranch(
        name=LINUX_AMD64, label="Linux", platform_dir=LINUX_AMD64,
        frontend="cerf-qt", launcher="launcher/launcher", forwarder="launcher.sh",
        builds_ce_apps=True, packed_artifact=True),
    MACOS_ARM64: HostBranch(
        name=MACOS_ARM64, label="macOS", platform_dir=MACOS_ARM64,
        frontend="CE Runtime Foundation.app/Contents/MacOS/CE Runtime Foundation",
        launcher="CE Runtime Foundation Launcher.app/Contents/MacOS/launcher", forwarder=None,
        builds_ce_apps=False, packed_artifact=True,
        cerf_json_defaults={HOST_KEY_KEY: [VK_RMENU]}),
}


class UnsupportedHost(Exception):
    pass


def all_branches() -> List[HostBranch]:
    return list(_BRANCHES.values())


def by_name(name: str) -> HostBranch:
    branch = _BRANCHES.get(name)
    if branch is None:
        raise UnsupportedHost("unknown CERF host branch {!r}".format(name))
    return branch


def from_config(config: dict) -> HostBranch:
    name = config.get(KEY)
    if name is None:
        if sys.platform == "win32":
            return _BRANCHES[WIN32_X86]
        raise UnsupportedHost("cerf.json names no {}".format(KEY))
    if not isinstance(name, str):
        raise UnsupportedHost("cerf.json {} is not a string".format(KEY))
    return by_name(name)


def release_marker(branch: HostBranch) -> str:
    return "Release-" + branch.platform_dir


def current() -> HostBranch:
    machine = platform.machine().lower()
    if sys.platform == "win32":
        return _BRANCHES[WIN32_X86]
    if sys.platform.startswith("linux") and machine in ("x86_64", "amd64"):
        return _BRANCHES[LINUX_AMD64]
    if sys.platform == "darwin" and machine == "arm64":
        return _BRANCHES[MACOS_ARM64]
    raise UnsupportedHost("no CERF host branch for {} on {}".format(sys.platform, machine))


def output_dir(root: Path, config: str, branch: HostBranch) -> Path:
    return root / "build" / config / branch.platform_dir


def stamp(cerf_json: Path, branch: HostBranch) -> None:
    data = json.loads(cerf_json.read_text(encoding="utf-8-sig")) if cerf_json.is_file() else {}
    if not isinstance(data, dict):
        raise ValueError("{} does not hold a JSON object".format(cerf_json))
    stamped = dict(data)
    stamped[KEY] = branch.name
    for key, value in branch.cerf_json_defaults.items():
        stamped.setdefault(key, value)
    if stamped == data:
        return
    cerf_json.write_text(json.dumps(stamped, indent=2) + "\n", encoding="utf-8")
