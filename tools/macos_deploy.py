from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import List, Optional

from tool_process import output_or_raise

FRAMEWORKS_REFERENCE = "@executable_path/../Frameworks/"
QT_CONF = "[Paths]\nPrefix = .\nPlugins = PlugIns\nQmlImports = Resources/qml\n"
MACH_O_MAGICS = (0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA)
SYSTEM_PREFIXES = ("/System/", "/usr/lib/")


class DeployError(Exception):
    pass


def _output(argv: List[object]) -> str:
    return output_or_raise(argv, DeployError)


def _is_mach_o(path: Path) -> bool:
    with open(str(path), "rb") as handle:
        head = handle.read(4)
    return len(head) == 4 and int.from_bytes(head, "big") in MACH_O_MAGICS


def _install_id(binary: Path) -> Optional[str]:
    lines = _output(["otool", "-D", binary]).splitlines()
    return lines[1].strip() if len(lines) > 1 else None


def _dependencies(binary: Path) -> List[str]:
    lines = _output(["otool", "-L", binary]).splitlines()[1:]
    return [line.strip().split(" (compatibility version")[0] for line in lines if line.strip()]


def _rpaths(binary: Path) -> List[str]:
    lines = _output(["otool", "-l", binary]).splitlines()
    paths = []
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH" and index + 2 < len(lines):
            match = re.match(r"\s*path (.*) \(offset \d+\)$", lines[index + 2])
            if match is None:
                raise DeployError("unreadable LC_RPATH in {}".format(binary))
            paths.append(match.group(1))
    return paths


def _bundled_reference(frameworks: Path, dependency: str) -> Optional[str]:
    match = re.search(r"([^/]+\.framework/.+)$", dependency)
    relative = match.group(1) if match else dependency.rsplit("/", 1)[-1]
    return FRAMEWORKS_REFERENCE + relative if (frameworks / relative).is_file() else None


def _mach_o_files(contents: Path) -> List[Path]:
    found = []
    for directory, _, files in os.walk(str(contents)):
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink() and _is_mach_o(path):
                found.append(path)
    return sorted(found)


def _localize(binary: Path, frameworks: Path) -> None:
    own_id = _install_id(binary)
    for dependency in _dependencies(binary):
        if dependency == own_id or dependency.startswith(SYSTEM_PREFIXES):
            continue
        target = _bundled_reference(frameworks, dependency)
        if target is None:
            raise DeployError("{} needs {}, which the bundle does not hold".format(binary, dependency))
        if target != dependency:
            _output(["install_name_tool", "-change", dependency, target, binary])
    if own_id is not None and frameworks in binary.parents:
        relative = binary.relative_to(frameworks).as_posix()
        _output(["install_name_tool", "-id", FRAMEWORKS_REFERENCE + relative, binary])
    for rpath in _rpaths(binary):
        _output(["install_name_tool", "-delete_rpath", rpath, binary])


def _sign(app: Path, frameworks: Path, binaries: List[Path]) -> None:
    for binary in binaries:
        if not any(parent.suffix == ".framework" for parent in binary.parents):
            _output(["codesign", "--force", "--sign", "-", binary])
    for framework in sorted(frameworks.glob("*.framework")):
        _output(["codesign", "--force", "--sign", "-", framework])
    _output(["codesign", "--force", "--sign", "-", app])
    _output(["codesign", "--verify", "--deep", "--strict", app])


def deploy(app: Path, homebrew_prefix: str, qml_dir: Path) -> None:
    macdeployqt = Path(homebrew_prefix) / "opt" / "qtbase" / "bin" / "macdeployqt"
    if not macdeployqt.is_file():
        raise DeployError("{} not found. Run brew install qtbase.".format(macdeployqt))
    _output([macdeployqt, app, "-always-overwrite", "-no-codesign",
             "-libpath={}".format(Path(homebrew_prefix) / "lib"),
             "-qmldir={}".format(qml_dir)])
    contents = app / "Contents"
    frameworks = contents / "Frameworks"
    binaries = _mach_o_files(contents)
    for binary in binaries:
        _localize(binary, frameworks)
    (contents / "Resources").mkdir(exist_ok=True)
    (contents / "Resources" / "qt.conf").write_text(QT_CONF, encoding="utf-8")
    _sign(app, frameworks, binaries)


def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print("usage: macos_deploy.py <bundle.app> <homebrew prefix> <qml dir>", file=sys.stderr)
        return 2
    try:
        deploy(Path(argv[0]), argv[1], Path(argv[2]))
    except (DeployError, OSError) as exc:
        print("macos_deploy: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
