from __future__ import annotations

import json
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from json_files import write_json
from product_facts import FRONTEND_NAME, PRODUCT_NAME

KEY = "host_branch"
HOST_KEY_KEY = "host_key"
WIN32_X86 = "win32-x86"
LINUX_AMD64 = "linux-amd64"
MACOS_ARM64 = "macos-arm64"
ANDROID_ARM64 = "android-arm64"
ANDROID_AMD64 = "android-amd64"
KEYLESS = WIN32_X86
ROOT_ENTRY = WIN32_X86
RELEASE_PREFIX = "Release-"
CI_BASE_URL = "https://cerf-bundles.dz3n.net/cerf_ci"
LATEST_NAME = "latest.json"
BRANCHES_KEY = "host_branches"
ENTRY_VERSION_KEYS = ("ver_major", "ver_minor", "ver_patch", "ver_build")
ENTRY_OBJECT_NAME_KEY = "object_name"
ENTRY_OBJECT_SIZE_KEY = "object_size"
ENTRY_OBJECT_SHA256_KEY = "object_sha256"
ENTRY_CHANGELOG_KEY = "changelog"

VK_RMENU = 0xA5


@dataclass(frozen=True)
class HostBranch:
    name: str
    label: str
    platform_dir: str
    frontend: str
    builds_ce_apps: bool
    packed_artifact: bool
    cerf_json_defaults: Dict[str, object] = field(default_factory=dict)
    package_file: bool = False
    ci_built: bool = True


_BRANCHES = {
    WIN32_X86: HostBranch(
        name=WIN32_X86, label="Windows", platform_dir="Win32",
        frontend=FRONTEND_NAME + ".exe",
        builds_ce_apps=True, packed_artifact=False),
    LINUX_AMD64: HostBranch(
        name=LINUX_AMD64, label="Linux", platform_dir=LINUX_AMD64,
        frontend=FRONTEND_NAME,
        builds_ce_apps=True, packed_artifact=True),
    MACOS_ARM64: HostBranch(
        name=MACOS_ARM64, label="macOS", platform_dir=MACOS_ARM64,
        frontend="{0}.app/Contents/MacOS/{0}".format(PRODUCT_NAME),
        builds_ce_apps=False, packed_artifact=True,
        cerf_json_defaults={HOST_KEY_KEY: [VK_RMENU]}),
    ANDROID_ARM64: HostBranch(
        name=ANDROID_ARM64, label="Android", platform_dir=ANDROID_ARM64,
        frontend=FRONTEND_NAME + ".apk",
        builds_ce_apps=False, packed_artifact=False, package_file=True),
    ANDROID_AMD64: HostBranch(
        name=ANDROID_AMD64, label="Android", platform_dir=ANDROID_AMD64,
        frontend=FRONTEND_NAME + ".apk",
        builds_ce_apps=False, packed_artifact=False, package_file=True, ci_built=False),
}


class UnsupportedHost(Exception):
    pass


def ci_branches() -> List[HostBranch]:
    return [branch for branch in _BRANCHES.values() if branch.ci_built]


def by_name(name: str) -> HostBranch:
    branch = _BRANCHES.get(name)
    if branch is None:
        raise UnsupportedHost("unknown CERF host branch {!r}".format(name))
    return branch


def release_marker(branch: HostBranch) -> str:
    return RELEASE_PREFIX + branch.platform_dir


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
    stamped = dict(data)
    stamped[KEY] = branch.name
    for key, value in branch.cerf_json_defaults.items():
        stamped.setdefault(key, value)
    if stamped == data:
        return
    write_json(cerf_json, stamped)


def cpp_header() -> str:
    branches = list(_BRANCHES.values())
    lines = ["#pragma once", "", "namespace host_branch_table {", "",
             "struct Row {", "    const char* name;", "    const char* platform_dir;",
             "    const unsigned char* host_key;", "};", "",
             'inline constexpr char kKey[]     = "{}";'.format(KEY),
             'inline constexpr char kHostKeyKey[] = "{}";'.format(HOST_KEY_KEY),
             'inline constexpr char kKeyless[] = "{}";'.format(KEYLESS),
             'inline constexpr char kKeylessFrontend[] = "{}";'.format(_BRANCHES[KEYLESS].frontend),
             'inline constexpr char kRootEntry[] = "{}";'.format(ROOT_ENTRY),
             'inline constexpr char kReleasePrefix[] = "{}";'.format(RELEASE_PREFIX),
             'inline constexpr char kCiBaseUrl[] = "{}";'.format(CI_BASE_URL),
             'inline constexpr char kLatestName[] = "{}";'.format(LATEST_NAME),
             'inline constexpr char kBranchesKey[] = "{}";'.format(BRANCHES_KEY),
             "inline constexpr const char* kEntryVersionKeys[] = {{{}}};".format(
                 ", ".join('"{}"'.format(key) for key in ENTRY_VERSION_KEYS)),
             'inline constexpr char kEntryObjectNameKey[] = "{}";'.format(ENTRY_OBJECT_NAME_KEY),
             'inline constexpr char kEntryObjectSizeKey[] = "{}";'.format(ENTRY_OBJECT_SIZE_KEY),
             'inline constexpr char kEntryObjectSha256Key[] = "{}";'.format(ENTRY_OBJECT_SHA256_KEY),
             'inline constexpr char kEntryChangelogKey[] = "{}";'.format(ENTRY_CHANGELOG_KEY), ""]
    for index, branch in enumerate(branches):
        vks = [int(vk) for vk in branch.cerf_json_defaults.get(HOST_KEY_KEY, [])]
        lines.append("inline constexpr unsigned char kHostKey{}[] = {{{}}};".format(
            index, ", ".join(str(vk) for vk in vks + [0])))
    lines += ["", "inline constexpr Row kRows[] = {"]
    lines += ['    {{"{}", "{}", kHostKey{}}},'.format(b.name, b.platform_dir, index)
              for index, b in enumerate(branches)]
    lines += ["};", "", "}", ""]
    return "\n".join(lines)


def write_cpp_header(path: Path) -> None:
    text = cpp_header()
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: List[str]) -> int:
    if len(argv) == 3 and argv[1] == "--cpp-header":
        write_cpp_header(Path(argv[2]))
        return 0
    if len(argv) == 4 and argv[1] == "--stamp":
        stamp(Path(argv[2]), by_name(argv[3]))
        return 0
    sys.stderr.write("usage: host_branch.py --cpp-header <file> | --stamp <cerf.json> <branch>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
