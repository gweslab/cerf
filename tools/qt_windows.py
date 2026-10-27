from __future__ import annotations

import hashlib
import os
import shutil
import string
import sys
import zipfile
from pathlib import Path
from typing import Callable, Dict, List

import tar_archives
import vs_toolchain
from json_files import json_digest, read_json_or_none, write_json
from qt_common import QT_DIR, STAMP_NAME, say
from tool_process import exit_code, output_or_raise, prepend_path, run_or_raise
from verified_download import DownloadError, Say, fetch_verified, partial_path

QT_VERSION = "6.8.4"
QT_MODULES = (
    ("qtbase", "532dfbf3fa3cbc68fa37441ea9e81c5009da044eaecda78ffaeafd8bd125532f"),
    ("qtshadertools", "379a70692b52903b82897869112c4759f7f6f4e76abc4987700e9cdd87c87ebd"),
    ("qtdeclarative", "e4e68aad4c07fbb9da670ecd621fabe51b56a2bfcce8da775653bdf8dcd768fc"),
    ("qtsvg", "e2a83b315b97eeaffa1d3f17e8192436541fe53e62171e82c7311c56ee9aac07"),
)
QT_SOURCE_URL = ("https://download.qt.io/archive/qt/6.8/{0}/submodules/"
                 "{1}-everywhere-opensource-src-{0}.tar.xz")
PATCH_COMMIT = "3df3aac758177b28843c4d1511a2bd7751fe82b6"
PATCH_URL = "https://github.com/crystalidea/qt6windows7/archive/{}.zip".format(PATCH_COMMIT)
PATCH_TREE = "e3bc950c394f42a73eb493d82b0004bbe9e89b6c0623d5e70e1eb7a655b7da7d"
PATCH_MODULE = "qtbase"
CONFIGURE = ("-release", "-opensource", "-confirm-license", "-opengl", "desktop", "-no-openssl",
             "-nomake", "tests", "-nomake", "examples")

class QtBuildError(Exception):
    pass


def prefix_dir(root: Path) -> Path:
    return root / QT_DIR / "{}-win7-x86".format(QT_VERSION)


def _wanted_stamp() -> dict:
    return {"version": QT_VERSION, "modules": dict(QT_MODULES), "patch_commit": PATCH_COMMIT,
            "patch_tree": PATCH_TREE, "configure": list(CONFIGURE)}


def _patch_entries(archive: zipfile.ZipFile) -> List[tuple]:
    entries = []
    for name in archive.namelist():
        relative = name.split("/", 1)[1] if "/" in name else ""
        if relative.startswith(PATCH_MODULE + "/") and not name.endswith("/"):
            entries.append((relative, name))
    return sorted(entries)


def _patch_tree(path: Path) -> str:
    try:
        archive = zipfile.ZipFile(str(path))
    except zipfile.BadZipFile:
        return ""
    total = hashlib.sha256()
    with archive:
        for relative, name in _patch_entries(archive):
            total.update(relative.encode("utf-8") + b"\0" + hashlib.sha256(archive.read(name)).digest())
    return total.hexdigest()


def _curl_download(url: str, destination: Path, report: Say) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = partial_path(destination)
    report("Downloading {}".format(url))
    run_or_raise(["curl.exe", "-fsSL", "--retry", "3", "-o", partial, url], QtBuildError,
                 "curl.exe for {}".format(url))
    partial.replace(destination)


def _fetch_sources(downloads: Path) -> Dict[str, Path]:
    archives = {}
    for module, sha256 in QT_MODULES:
        archive = downloads / "{}-everywhere-opensource-src-{}.tar.xz".format(module, QT_VERSION)
        archives[module] = fetch_verified(QT_SOURCE_URL.format(QT_VERSION, module), archive, sha256, say,
                                          _curl_download)
    archives["patches"] = fetch_verified(PATCH_URL, downloads / "qt6windows7-{}.zip".format(PATCH_COMMIT),
                                         PATCH_TREE, say, _curl_download, _patch_tree)
    return archives


def _unpack(archives: Dict[str, Path], src: Path) -> None:
    for module, _sha256 in QT_MODULES:
        say("Unpacking {}".format(module))
        tar_archives.extract(archives[module], src)
        (src / "{}-everywhere-src-{}".format(module, QT_VERSION)).rename(src / module)
    count = 0
    with zipfile.ZipFile(str(archives["patches"])) as archive:
        for relative, name in _patch_entries(archive):
            (src / relative).write_bytes(archive.read(name))
            count += 1
    say("Applied {} qt6windows7 files to {}".format(count, PATCH_MODULE))


def _vcvars_environment(toolchain) -> Dict[str, str]:
    vcvars = Path(toolchain.instance["installationPath"]) / "VC" / "Auxiliary" / "Build" / \
        "vcvarsall.bat"
    if not vcvars.is_file():
        raise QtBuildError("{} not found".format(vcvars))
    command = '"{}" x86 -vcvars_ver={} >nul && set'.format(vcvars, toolchain.tools_version)
    listing = output_or_raise('cmd /u /s /c "' + command + '"', QtBuildError,
                              "vcvarsall.bat x86 -vcvars_ver={}".format(toolchain.tools_version), encoding=None)
    env = {}
    for line in listing.decode("utf-16-le", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep and key:
            env[key.upper()] = value
    return prepend_path(env, toolchain.cmake.parent, toolchain.ninja.parent)


def _free_drive() -> str:
    for letter in reversed(string.ascii_uppercase[3:]):
        if not os.path.exists(letter + ":\\"):
            return letter + ":"
    raise QtBuildError("no free drive letter for the short Qt build path")


def _run_batch(batch: Path, args: List[str], cwd: Path, env: Dict[str, str]) -> None:
    quoted = " ".join('"{}"'.format(part) for part in [str(batch)] + args)
    run_or_raise('cmd /s /c "' + quoted + '"', QtBuildError, batch.name, cwd, env)


def _build(short: Path, prefix: Path, cmake: Path, env: Dict[str, str],
           heartbeat: Callable[[], None]) -> None:
    for module, _sha256 in QT_MODULES:
        build = short / "b" / module
        build.mkdir(parents=True)
        say("Configuring {}".format(module))
        if module == "qtbase":
            _run_batch(short / "src" / "qtbase" / "configure.bat",
                       ["-prefix", str(prefix)] + list(CONFIGURE), build, env)
        else:
            _run_batch(prefix / "bin" / "qt-configure-module.bat", [str(short / "src" / module)],
                       build, env)
        heartbeat()
        say("Building {}".format(module))
        run_or_raise([cmake, "--build", ".", "--parallel"], QtBuildError, cwd=build, env=env)
        heartbeat()
        run_or_raise([cmake, "--install", "."], QtBuildError, cwd=build, env=env)
        heartbeat()


def ensure(root: Path, toolchain, heartbeat: Callable[[], None]) -> Path:
    prefix = prefix_dir(root)
    stamp = prefix / STAMP_NAME
    wanted = _wanted_stamp()
    if read_json_or_none(stamp) == wanted:
        return prefix
    say("Building Qt {} for Windows 7 x86 into {}. The first build takes a long time.".format(
        QT_VERSION, prefix))
    archives = _fetch_sources(root / QT_DIR / "downloads")
    work = root / QT_DIR / "work"
    for stale in (work, prefix):
        if stale.exists():
            shutil.rmtree(str(stale))
    (work / "src").mkdir(parents=True)
    _unpack(archives, work / "src")
    env = _vcvars_environment(toolchain)
    drive = _free_drive()
    run_or_raise(["subst", drive, work], QtBuildError)
    try:
        _build(Path(drive + "\\"), prefix, toolchain.cmake, env, heartbeat)
    finally:
        exit_code(["subst", drive, "/D"])
    write_json(stamp, wanted)
    shutil.rmtree(str(work))
    say("Qt {} installed into {}".format(QT_VERSION, prefix))
    return prefix


def cache_outputs() -> List[str]:
    return ["path={}".format(prefix_dir(Path(".")).as_posix()), "key={}".format(json_digest(_wanted_stamp()))]


def main(argv: List[str]) -> int:
    if argv == ["--cache-outputs"]:
        print("\n".join(cache_outputs()))
        return 0
    if argv == ["--ensure"]:
        try:
            toolchain = vs_toolchain.require("Qt {}".format(QT_VERSION))
            ensure(Path(__file__).resolve().parent.parent, toolchain, lambda: None)
        except (vs_toolchain.ToolchainError, QtBuildError, DownloadError, OSError) as exc:
            say("FAILED! {}".format(exc))
            return 1
        return 0
    sys.stderr.write("usage: qt_windows.py --cache-outputs | --ensure\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
