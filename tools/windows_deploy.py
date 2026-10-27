from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from product_facts import QML_SOURCE_DIR
from tool_process import run_or_raise

CRT_FOLDER = "Microsoft.VC143.CRT"


class DeployError(Exception):
    pass


def _version_key(text: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text))


def _newest(directories: List[Path]) -> Optional[Path]:
    present = [d for d in directories if d.is_dir()]
    return max(present, key=lambda d: _version_key(d.parent.parent.name)) if present else None


def vc_runtime_dir(toolchain) -> Path:
    redist = Path(toolchain.instance["installationPath"]) / "VC" / "Redist" / "MSVC"
    found = _newest([d / "x86" / CRT_FOLDER for d in redist.iterdir()]) if redist.is_dir() else None
    if found is None:
        raise DeployError("no x86\\{} under {}".format(CRT_FOLDER, redist))
    return found


def ucrt_dir() -> Path:
    kits = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Windows Kits" / "10" / "Redist"
    candidates = sorted((d for d in kits.iterdir() if d.is_dir()), key=lambda d: _version_key(d.name),
                        reverse=True) if kits.is_dir() else []
    for version in candidates:
        dlls = version / "ucrt" / "DLLs" / "x86"
        if dlls.is_dir():
            return dlls
    raise DeployError("no ucrt\\DLLs\\x86 under {}".format(kits))


def _copy_dlls(source: Path, out: Path) -> int:
    count = 0
    for dll in sorted(source.glob("*.dll")):
        shutil.copy2(str(dll), str(out / dll.name))
        count += 1
    if count == 0:
        raise DeployError("{} holds no DLL".format(source))
    return count


def deploy(root: Path, exe: Path, qt_prefix: Path, toolchain) -> None:
    windeployqt = qt_prefix / "bin" / "windeployqt.exe"
    run_or_raise([windeployqt, "--release", "--no-compiler-runtime", "--no-translations", "--qmldir",
                  root / QML_SOURCE_DIR, exe], DeployError, "windeployqt")
    runtime = vc_runtime_dir(toolchain)
    ucrt = ucrt_dir()
    copied = _copy_dlls(runtime, exe.parent) + _copy_dlls(ucrt, exe.parent)
    print("[DEPLOY] Qt from {}; {} runtime DLLs from {} and {}".format(qt_prefix, copied, runtime,
                                                                     ucrt), flush=True)
