from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, List, Tuple

import qt_online_repository
from host_branch import ANDROID_AMD64, ANDROID_ARM64
from json_files import json_digest
from qt_common import QT_DIR, STAMP_NAME
from qt_online_repository import QT_VERSION, Archive

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


def target_prefix(root: Path, branch_name: str) -> Path:
    return root / QT_DIR / "{}-{}".format(QT_VERSION, branch_name)


def ensure(root: Path, branch_name: str, cmake: Path, heartbeat: Callable[[], None]) -> Tuple[Path, Path]:
    target_folder, target_archives = TARGETS[branch_name]
    target = qt_online_repository.install(target_prefix(root, branch_name), target_folder, target_archives, cmake,
                                          qt_online_repository.downloads_dir(root), heartbeat)
    host = qt_online_repository.ensure_host(root, cmake, heartbeat)
    return target, host


def cache_outputs(branch_name: str) -> List[str]:
    _, target_archives = TARGETS[branch_name]
    key = json_digest([qt_online_repository.wanted_stamp(target_archives),
                       qt_online_repository.wanted_stamp(qt_online_repository.host_archives())])
    target = target_prefix(Path("."), branch_name)
    host = qt_online_repository.host_prefix(Path("."))
    return ["key={}".format(key), "target-stamp={}".format((target / STAMP_NAME).as_posix()),
            "host-stamp={}".format((host / STAMP_NAME).as_posix()),
            "paths<<CERF_QT_PATHS", target.as_posix(), host.as_posix(), "CERF_QT_PATHS"]


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--cache-outputs" or sys.argv[2] not in TARGETS or \
            not qt_online_repository.host_supported():
        raise SystemExit("usage: qt_android.py --cache-outputs <{}> (on {})".format(
            "|".join(TARGETS), "|".join(qt_online_repository.HOSTS)))
    print("\n".join(cache_outputs(sys.argv[2])))
