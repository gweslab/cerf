from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable, List, Tuple

from host_branch import LINUX_AMD64
from json_files import json_digest, read_json_or_none, write_json
from qt_common import QT_DIR, STAMP_NAME, say
from tool_process import run_or_raise
from verified_download import fetch_verified

QT_VERSION = "6.12.0"
PACKAGE_VERSION = "6.12.0-0-202609280346"
REPOSITORY = "https://download.qt.io/online/qtsdkrepository/"

Archive = Tuple[str, str, str]

LINUX_HOST_FOLDER = "linux_x64/desktop/qt6_6120/qt6_6120"
LINUX_DESKTOP_ARCHIVES: Tuple[Archive, ...] = (
    ("qt.qt6.6120.linux_gcc_64", "qtbase-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "943023b929d0c08eafe7341700b5ed7601284410b7afd6093f950be291d1d7cd"),
    ("qt.qt6.6120.linux_gcc_64", "qtsvg-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "22a7404505a2883c54556183f19adfff1cdbea30664e34bfd4171180802142e9"),
    ("qt.qt6.6120.linux_gcc_64", "qtdeclarative-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "0c719e17ea9fbd37aa615595149dca2578985656433f27bf2846cffe4b687d3e"),
    ("qt.qt6.6120.linux_gcc_64", "qtwayland-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "14c0dc4c8147cf9f7f64909b27ae5c9ab2aaa8ad6625bc2248c693c2a327ab5b"),
    ("qt.qt6.6120.linux_gcc_64", "icu-linux-Rhel8.6-x86_64.7z",
     "1fdbcd67b1760f3a3f031c64637a9f19992aed2f35aa615e12a468f8c655d4da"),
)
LINUX_HOST_ARCHIVES: Tuple[Archive, ...] = LINUX_DESKTOP_ARCHIVES + (
    ("qt.qt6.6120.linux_gcc_64", "qtdoc-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "05b4375677be48ab3975453f097643761e0483c5e8ec4a025d8d9906841b4873"),
    ("qt.qt6.6120.linux_gcc_64", "qttools-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "5d6f90961df3a1e5a57fac69bbbe6983860bad11c419a49736b84914588b4334"),
    ("qt.qt6.6120.linux_gcc_64", "qttranslations-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "bd10fbbce93b076d9bc29576f41e9ccbaf3f7782625f9bebb418d2d9b9f97c47"),
    ("qt.qt6.6120.addons.qtshadertools.linux_gcc_64",
     "qtshadertools-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "66892450a2baf559b230778f34f879db76d93fdc58b4241522a5d495643f00a5"),
)

WINDOWS_HOST_FOLDER = "windows_x86/desktop/qt6_6120/qt6_6120_msvc2022_64"
WINDOWS_HOST_ARCHIVES: Tuple[Archive, ...] = (
    ("qt.qt6.6120.win64_msvc2022_64", "qtbase-Windows-Windows_11_24H2-MSVC2022-Windows-Windows_11_24H2-X86_64.7z",
     "219d1b86def3be418e31d704572bc4acc91b2ec373c65595c9fb12b42bf098dc"),
    ("qt.qt6.6120.win64_msvc2022_64", "qtsvg-Windows-Windows_11_24H2-MSVC2022-Windows-Windows_11_24H2-X86_64.7z",
     "dfcad02224b71724e3314d0bc3ffc0b862dfa6e02bc4aadd39f1738f6c364c79"),
    ("qt.qt6.6120.win64_msvc2022_64",
     "qtdeclarative-Windows-Windows_11_24H2-MSVC2022-Windows-Windows_11_24H2-X86_64.7z",
     "258146e9972fadbc1162cda31c7d7ed7e627f5022b2a848f2edb84d9c2ce27db"),
    ("qt.qt6.6120.win64_msvc2022_64", "qtdoc-Windows-Windows_11_24H2-MSVC2022-Windows-Windows_11_24H2-X86_64.7z",
     "ebe18226f9d1477177746d53d53094108f7747583ceb3b1c1d2c5d077dac80eb"),
    ("qt.qt6.6120.win64_msvc2022_64", "qttools-Windows-Windows_11_24H2-MSVC2022-Windows-Windows_11_24H2-X86_64.7z",
     "73328e361429378df518f391ebe4d82c51e833f4d5a951692768ab5a5a1d7da5"),
    ("qt.qt6.6120.win64_msvc2022_64",
     "qttranslations-Windows-Windows_11_24H2-MSVC2022-Windows-Windows_11_24H2-X86_64.7z",
     "328321e8879a3dc119775b4404d6e32ec2a361696e73f760540a732921507917"),
    ("qt.qt6.6120.win64_msvc2022_64", "d3dcompiler_47-x64.7z",
     "067506b5424849133fb4291737da010ff336be91195fd6299f47096fbf413a50"),
    ("qt.qt6.6120.win64_msvc2022_64", "opengl32sw-64-mesa_11_2_2-signed_sha256.7z",
     "edc94ad93e8bb6a97b27932fe01a71c37dd435690eeeff2d0085880e1eda8be6"),
    ("qt.qt6.6120.addons.qtshadertools.win64_msvc2022_64",
     "qtshadertools-Windows-Windows_11_24H2-MSVC2022-Windows-Windows_11_24H2-X86_64.7z",
     "dfceb86842d60a81ff75c1c2c98d49d186efc5c6cc49f0225b3b2ed699beca4b"),
)

ARCHIVE_DESTINATIONS = {
    "icu-linux-Rhel8.6-x86_64.7z": "lib",
}

HOSTS = {
    "linux": ("linux-x64", LINUX_HOST_FOLDER, LINUX_HOST_ARCHIVES),
    "win32": ("windows-x64", WINDOWS_HOST_FOLDER, WINDOWS_HOST_ARCHIVES),
}


class QtFetchError(Exception):
    pass


def _fetch(folder: str, archives: Tuple[Archive, ...], downloads: Path) -> List[Path]:
    return [fetch_verified("{}{}/{}/{}{}".format(REPOSITORY, folder, package, PACKAGE_VERSION, name),
                           downloads / name, sha256, say)
            for package, name, sha256 in archives]


def wanted_stamp(archives: Tuple[Archive, ...]) -> dict:
    wanted = {"version": PACKAGE_VERSION, "archives": {name: sha256 for _, name, sha256 in archives}}
    destinations = {name: ARCHIVE_DESTINATIONS[name] for _, name, _ in archives if name in ARCHIVE_DESTINATIONS}
    if destinations:
        wanted["destinations"] = destinations
    return wanted


def install(prefix: Path, folder: str, archives: Tuple[Archive, ...], cmake: Path, downloads: Path,
            heartbeat: Callable[[], None]) -> Path:
    stamp = prefix / STAMP_NAME
    wanted = wanted_stamp(archives)
    if read_json_or_none(stamp) == wanted:
        return prefix
    paths = _fetch(folder, archives, downloads)
    heartbeat()
    if prefix.exists():
        shutil.rmtree(str(prefix))
    prefix.mkdir(parents=True)
    for path in paths:
        say("Unpacking {}".format(path.name))
        destination = prefix / ARCHIVE_DESTINATIONS.get(path.name, "")
        destination.mkdir(parents=True, exist_ok=True)
        run_or_raise([cmake, "-E", "tar", "xf", path], QtFetchError, "cmake -E tar xf {}".format(path.name),
                     destination)
        heartbeat()
    write_json(stamp, wanted)
    say("Qt {} installed into {}".format(QT_VERSION, prefix))
    return prefix


def downloads_dir(root: Path) -> Path:
    return root / QT_DIR / "downloads"


def host_supported() -> bool:
    return sys.platform in HOSTS


def host_prefix(root: Path) -> Path:
    return root / QT_DIR / "{}-{}".format(QT_VERSION, HOSTS[sys.platform][0])


def host_archives() -> Tuple[Archive, ...]:
    return HOSTS[sys.platform][2]


def ensure_host(root: Path, cmake: Path, heartbeat: Callable[[], None]) -> Path:
    _, folder, archives = HOSTS[sys.platform]
    return install(host_prefix(root), folder, archives, cmake, downloads_dir(root), heartbeat)


def linux_desktop_prefix(root: Path) -> Path:
    return root / QT_DIR / "{}-{}".format(QT_VERSION, LINUX_AMD64)


def ensure_linux_desktop(root: Path, cmake: Path, heartbeat: Callable[[], None]) -> Path:
    return install(linux_desktop_prefix(root), LINUX_HOST_FOLDER, LINUX_DESKTOP_ARCHIVES, cmake,
                   downloads_dir(root), heartbeat)


def linux_desktop_cache_outputs() -> List[str]:
    prefix = linux_desktop_prefix(Path("."))
    return ["key={}".format(json_digest(wanted_stamp(LINUX_DESKTOP_ARCHIVES))), "path={}".format(prefix.as_posix()),
            "stamp={}".format((prefix / STAMP_NAME).as_posix())]


if __name__ == "__main__":
    if sys.argv[1:] != ["--cache-outputs"]:
        raise SystemExit("usage: qt_online_repository.py --cache-outputs")
    print("\n".join(linux_desktop_cache_outputs()))
