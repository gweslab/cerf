from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

MIN_TOOLS_VERSION = (14, 30)


@dataclass
class VsToolchain:
    vswhere: Path
    instance: Optional[dict] = None
    tools_version: Optional[str] = None
    platform_toolset: Optional[str] = None
    installed: List[str] = field(default_factory=list)
    msbuild: Optional[Path] = None
    cmake: Optional[Path] = None
    ninja: Optional[Path] = None


def _version_key(text: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text))


def _vswhere(vswhere: Path, *args: str) -> str:
    return subprocess.run([str(vswhere)] + list(args), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=False).stdout


def find() -> VsToolchain:
    program_files = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vswhere = Path(program_files) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    toolchain = VsToolchain(vswhere=vswhere)
    if not vswhere.is_file():
        return toolchain

    raw = _vswhere(vswhere, "-all", "-prerelease", "-requires", "Microsoft.Component.MSBuild",
                   "-format", "json")
    try:
        instances = json.loads(raw) if raw.strip() else []
    except ValueError:
        instances = []
    instances.sort(key=lambda i: _version_key(i.get("installationVersion", "0")), reverse=True)
    for candidate in instances:
        tools_root = Path(candidate["installationPath"]) / "VC" / "Tools" / "MSVC"
        if not tools_root.is_dir():
            continue
        names = sorted(p.name for p in tools_root.iterdir() if p.is_dir())
        toolchain.installed.append("{}: {}".format(candidate.get("displayName", "?"),
                                                   ", ".join(names)))
        usable = [n for n in names
                  if not n.startswith("14.51.") and _version_key(n)[:2] >= MIN_TOOLS_VERSION]
        if usable:
            toolchain.instance = candidate
            toolchain.tools_version = min(usable, key=_version_key)
            break
    if toolchain.tools_version is None:
        return toolchain

    major_minor = re.match(r"^(\d\d)\.(\d)", toolchain.tools_version)
    toolset = "v" + major_minor.group(1) + major_minor.group(2)
    toolchain.platform_toolset = "v143" if toolset == "v144" else toolset

    root = toolchain.instance["installationPath"]
    found = _vswhere(vswhere, "-path", root, "-find", r"MSBuild\**\Bin\amd64\MSBuild.exe")
    first = next((line.strip() for line in found.splitlines() if line.strip()), None)
    toolchain.msbuild = Path(first) if first else None
    cmake_tools = Path(root) / "Common7" / "IDE" / "CommonExtensions" / "Microsoft" / "CMake"
    toolchain.cmake = cmake_tools / "CMake" / "bin" / "cmake.exe"
    toolchain.ninja = cmake_tools / "Ninja" / "ninja.exe"
    return toolchain


def min_tools_version_text() -> str:
    return "{}.{}".format(*MIN_TOOLS_VERSION)
