from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable, List, Tuple

from host_branch import ANDROID_AMD64, ANDROID_ARM64
from json_files import json_digest, read_json_or_none, write_json
from qt_common import QT_DIR, STAMP_NAME, say
from tool_process import run_or_raise
from verified_download import fetch_verified

QT_VERSION = "6.12.0"
PACKAGE_VERSION = "6.12.0-0-202609280346"
REPOSITORY = "https://download.qt.io/online/qtsdkrepository/"

Archive = Tuple[str, str, str]

ARM64_FOLDER = "all_os/android/qt6_6120/qt6_6120_arm64_v8a"
ARM64_ARCHIVES: Tuple[Archive, ...] = (
    ("qt.qt6.6120.android_arm64_v8a", "qtbase-MacOS-MacOS_15-Clang-Android-Android_ANY-ARM64.7z",
     "6c55d891f1685bdafb22425cc209b304eacb04b6bc774fd3965ac1326ffa1cc2"),
    ("qt.qt6.6120.android_arm64_v8a", "qtsvg-MacOS-MacOS_15-Clang-Android-Android_ANY-ARM64.7z",
     "64d8f5264ded615f84b875a4d39ab5bd1523eaa1ca7203d6939d46d716169304"),
    ("qt.qt6.6120.android_arm64_v8a", "qtdeclarative-MacOS-MacOS_15-Clang-Android-Android_ANY-ARM64.7z",
     "f70b11175ccce08e9caad65c02b7153e4efcdba2945e04cbc4b44df5d2c1ee35"),
    ("qt.qt6.6120.android_arm64_v8a", "qtdoc-MacOS-MacOS_15-Clang-Android-Android_ANY-ARM64.7z",
     "3520c694d487f1bacc07dbcd2232fae1af5970ac3c4a84ca7a3857634dfd11cc"),
    ("qt.qt6.6120.android_arm64_v8a", "qttools-MacOS-MacOS_15-Clang-Android-Android_ANY-ARM64.7z",
     "ca3c225708611efe865931a58eb8b17307f4250779d03152c0020b4b61471179"),
    ("qt.qt6.6120.android_arm64_v8a", "qttranslations-MacOS-MacOS_15-Clang-Android-Android_ANY-ARM64.7z",
     "0e438bac673c5e3d324f93f095dd1f380384c8eba66efb96011821bc811d5856"),
    ("qt.qt6.6120.addons.qtshadertools.android_arm64_v8a",
     "qtshadertools-MacOS-MacOS_15-Clang-Android-Android_ANY-ARM64.7z",
     "48504614f5da40a6ddf94ff72d42b972c4183ce289643b46ff2b4522b5203f90"),
)

AMD64_FOLDER = "all_os/android/qt6_6120/qt6_6120_x86_64"
AMD64_ARCHIVES: Tuple[Archive, ...] = (
    ("qt.qt6.6120.android_x86_64", "qtbase-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z",
     "347dd1c17a499362b1eade91e5239c676cf2612cd94f4d9cc20fb4f9aa299cc8"),
    ("qt.qt6.6120.android_x86_64", "qtsvg-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z",
     "4f9e5f331356e966dc2d0c357bba1fc607ac05536416d8f4bd9448f2d584102c"),
    ("qt.qt6.6120.android_x86_64", "qtdeclarative-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z",
     "16724585b3df40b0a472a04a3a4f05430bd3bb82cb264a4cbbd2e2b4ccf3503f"),
    ("qt.qt6.6120.android_x86_64", "qtdoc-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z",
     "17a404b044dbd27c2a820a043c3977fc475e5e4f331d5d1bd615450d91903dd5"),
    ("qt.qt6.6120.android_x86_64", "qttools-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z",
     "ccda9de2379e4c88bf35c8532217d14c394a728195f910992466b2a341d91f07"),
    ("qt.qt6.6120.android_x86_64", "qttranslations-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z",
     "a871905f92021e640c0d9562afb94ee44045e0b28ae148f9117a9d0faec00f7d"),
    ("qt.qt6.6120.addons.qtshadertools.android_x86_64",
     "qtshadertools-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z",
     "a7803edcb8871491cf39670f21aeeed88298e6af2cafaf86b0c7825a68383447"),
)

TARGETS = {
    ANDROID_ARM64: (ARM64_FOLDER, ARM64_ARCHIVES),
    ANDROID_AMD64: (AMD64_FOLDER, AMD64_ARCHIVES),
}

LINUX_HOST_FOLDER = "linux_x64/desktop/qt6_6120/qt6_6120"
LINUX_HOST_ARCHIVES: Tuple[Archive, ...] = (
    ("qt.qt6.6120.linux_gcc_64", "qtbase-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "943023b929d0c08eafe7341700b5ed7601284410b7afd6093f950be291d1d7cd"),
    ("qt.qt6.6120.linux_gcc_64", "qtsvg-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "22a7404505a2883c54556183f19adfff1cdbea30664e34bfd4171180802142e9"),
    ("qt.qt6.6120.linux_gcc_64", "qtdeclarative-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "0c719e17ea9fbd37aa615595149dca2578985656433f27bf2846cffe4b687d3e"),
    ("qt.qt6.6120.linux_gcc_64", "qtdoc-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "05b4375677be48ab3975453f097643761e0483c5e8ec4a025d8d9906841b4873"),
    ("qt.qt6.6120.linux_gcc_64", "qttools-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "5d6f90961df3a1e5a57fac69bbbe6983860bad11c419a49736b84914588b4334"),
    ("qt.qt6.6120.linux_gcc_64", "qttranslations-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "bd10fbbce93b076d9bc29576f41e9ccbaf3f7782625f9bebb418d2d9b9f97c47"),
    ("qt.qt6.6120.linux_gcc_64", "qtwayland-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z",
     "14c0dc4c8147cf9f7f64909b27ae5c9ab2aaa8ad6625bc2248c693c2a327ab5b"),
    ("qt.qt6.6120.linux_gcc_64", "icu-linux-Rhel8.6-x86_64.7z",
     "1fdbcd67b1760f3a3f031c64637a9f19992aed2f35aa615e12a468f8c655d4da"),
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


def _wanted_stamp(archives: Tuple[Archive, ...]) -> dict:
    wanted = {"version": PACKAGE_VERSION, "archives": {name: sha256 for _, name, sha256 in archives}}
    destinations = {name: ARCHIVE_DESTINATIONS[name] for _, name, _ in archives if name in ARCHIVE_DESTINATIONS}
    if destinations:
        wanted["destinations"] = destinations
    return wanted


def _install(prefix: Path, folder: str, archives: Tuple[Archive, ...], cmake: Path, downloads: Path,
             heartbeat: Callable[[], None]) -> Path:
    stamp = prefix / STAMP_NAME
    wanted = _wanted_stamp(archives)
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


def host_supported() -> bool:
    return sys.platform in HOSTS


def prefix_dirs(root: Path, branch_name: str) -> Tuple[Path, Path]:
    return (root / QT_DIR / "{}-{}".format(QT_VERSION, branch_name),
            root / QT_DIR / "{}-{}".format(QT_VERSION, HOSTS[sys.platform][0]))


def ensure(root: Path, branch_name: str, cmake: Path, heartbeat: Callable[[], None]) -> Tuple[Path, Path]:
    downloads = root / QT_DIR / "downloads"
    target_prefix, host_prefix = prefix_dirs(root, branch_name)
    target_folder, target_archives = TARGETS[branch_name]
    target = _install(target_prefix, target_folder, target_archives, cmake, downloads, heartbeat)
    _, host_folder, host_archives = HOSTS[sys.platform]
    host = _install(host_prefix, host_folder, host_archives, cmake, downloads, heartbeat)
    return target, host


def cache_outputs(branch_name: str) -> List[str]:
    _, target_archives = TARGETS[branch_name]
    _, _, host_archives = HOSTS[sys.platform]
    key = json_digest([_wanted_stamp(target_archives), _wanted_stamp(host_archives)])
    target, host = prefix_dirs(Path("."), branch_name)
    return ["key={}".format(key), "target-stamp={}".format((target / STAMP_NAME).as_posix()),
            "host-stamp={}".format((host / STAMP_NAME).as_posix()),
            "paths<<CERF_QT_PATHS", target.as_posix(), host.as_posix(), "CERF_QT_PATHS"]


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--cache-outputs" or sys.argv[2] not in TARGETS or not host_supported():
        raise SystemExit("usage: qt_android.py --cache-outputs <{}> (on {})".format("|".join(TARGETS), "|".join(HOSTS)))
    print("\n".join(cache_outputs(sys.argv[2])))
