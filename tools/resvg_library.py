from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List

import rust_toolchain
import tar_archives
from host_branch import ANDROID_AMD64, ANDROID_ARM64, LINUX_AMD64, MACOS_ARM64, WIN32_X86
from json_files import json_digest, read_json_or_none, write_json
from tool_log import tagged
from tool_process import failure_text
from verified_download import fetch_verified

RESVG_VERSION = "0.48.1"
ARCHIVE = "resvg-{}.tar.xz".format(RESVG_VERSION)
ARCHIVE_SHA256 = "13ed5a2bae7a01156288ecae5bf944cf7d1c572742c19fc68027947a4d87294c"
ARCHIVE_URL = "https://github.com/linebender/resvg/releases/download/v{}/{}".format(RESVG_VERSION, ARCHIVE)
RESVG_DIR = Path("third_party") / "resvg"
STAMP_NAME = "cerf_resvg.json"
LINK_LIBRARIES = "link_libraries.txt"
NATIVE_LIBS_NOTE = "note: native-static-libs:"


@dataclass(frozen=True)
class RustTarget:
    triple: str
    toolchain: str
    build_std: bool


TARGETS = {
    WIN32_X86: RustTarget("i686-win7-windows-msvc", rust_toolchain.NIGHTLY, True),
    LINUX_AMD64: RustTarget("x86_64-unknown-linux-gnu", rust_toolchain.STABLE, False),
    MACOS_ARM64: RustTarget("aarch64-apple-darwin", rust_toolchain.STABLE, False),
    ANDROID_ARM64: RustTarget("aarch64-linux-android", rust_toolchain.STABLE, False),
    ANDROID_AMD64: RustTarget("x86_64-linux-android", rust_toolchain.STABLE, False),
}


class ResvgError(Exception):
    pass


say = tagged("RESVG")


def _fetch(downloads: Path) -> Path:
    return fetch_verified(ARCHIVE_URL, downloads / ARCHIVE, ARCHIVE_SHA256, say)


def _unpack(archive: Path, source: Path) -> None:
    marker = source / "Cargo.lock"
    if marker.is_file():
        return
    if source.exists():
        shutil.rmtree(str(source))
    staging = source.with_name(source.name + ".unpack")
    if staging.exists():
        shutil.rmtree(str(staging))
    staging.mkdir(parents=True)
    tar_archives.extract(archive, staging)
    (staging / "resvg-{}".format(RESVG_VERSION)).replace(source)
    staging.rmdir()


def _link_libraries(note_line: str) -> List[str]:
    libraries: List[str] = []
    tokens = note_line.split()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "-framework" and i + 1 < len(tokens):
            libraries.append("-framework " + tokens[i + 1])
            i += 2
            continue
        if token.startswith("-l"):
            libraries.append(token[2:])
        elif token.lower().endswith(".lib"):
            libraries.append(token[:-4])
        i += 1
    return libraries


def _library_name(triple: str) -> str:
    return "resvg.lib" if triple.endswith("-msvc") else "libresvg.a"


def _wanted_stamp(target: RustTarget) -> dict:
    return {"version": RESVG_VERSION, "toolchain": target.toolchain, "build_std": target.build_std}


def prefix_dir(root: Path, target: RustTarget) -> Path:
    return root / RESVG_DIR / RESVG_VERSION / target.triple


def build(root: Path, branch_name: str, env: Dict[str, str], heartbeat: Callable[[], None]) -> Path:
    target = TARGETS[branch_name]
    base = root / RESVG_DIR / RESVG_VERSION
    source = base / "src"
    prefix = prefix_dir(root, target)
    stamp = prefix / STAMP_NAME
    wanted = _wanted_stamp(target)
    if read_json_or_none(stamp) == wanted:
        return prefix
    rust = rust_toolchain.RustToolchain(root, heartbeat)
    try:
        if target.build_std:
            rust.ensure(target.toolchain, [], ["rust-src"])
        else:
            rust.ensure(target.toolchain, [target.triple], [])
    except rust_toolchain.RustError as exc:
        raise ResvgError(str(exc))
    _unpack(_fetch(root / RESVG_DIR / "downloads"), source)
    heartbeat()
    target_dir = base / "target"
    argv: List[str] = [str(rust.cargo()), "+" + target.toolchain, "rustc"]
    if target.build_std:
        argv += ["-Z", "build-std=std,panic_abort"]
    argv += ["--manifest-path", str(source / "crates" / "c-api" / "Cargo.toml"), "--lib",
             "--crate-type", "staticlib", "--release", "--locked", "--target", target.triple,
             "--target-dir", str(target_dir), "--", "--print", "native-static-libs"]
    say("Building resvg {} for {}".format(RESVG_VERSION, target.triple))
    run_env = rust.environment(env)
    process = subprocess.Popen(argv, env=run_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, encoding="utf-8", errors="replace")
    note = ""
    for line in process.stdout:
        print(line, end="", flush=True)
        if NATIVE_LIBS_NOTE in line:
            note = line.split(NATIVE_LIBS_NOTE, 1)[1]
    code = process.wait()
    heartbeat()
    if code != 0:
        raise ResvgError(failure_text("cargo rustc for resvg {}".format(target.triple), code))
    if not note:
        raise ResvgError("resvg: rustc printed no native-static-libs line")
    built = target_dir / target.triple / "release" / _library_name(target.triple)
    if prefix.exists():
        shutil.rmtree(str(prefix))
    (prefix / "include").mkdir(parents=True)
    (prefix / "lib").mkdir()
    shutil.copy2(str(source / "crates" / "c-api" / "resvg.h"), str(prefix / "include" / "resvg.h"))
    shutil.copy2(str(built), str(prefix / "lib" / built.name))
    (prefix / LINK_LIBRARIES).write_text("\n".join(_link_libraries(note)) + "\n", encoding="utf-8")
    write_json(stamp, wanted)
    say("resvg {} ready in {}".format(RESVG_VERSION, prefix))
    return prefix


def cmake_options(root: Path, branch_name: str, env: Dict[str, str], heartbeat: Callable[[], None]) -> List[str]:
    return ["-DCERFQT_RESVG_PREFIX={}".format(build(root, branch_name, env, heartbeat).as_posix())]


def cache_outputs(branch_name: str) -> List[str]:
    target = TARGETS[branch_name]
    prefix = prefix_dir(Path("."), target)
    return ["path={}".format(prefix.as_posix()), "stamp={}".format((prefix / STAMP_NAME).as_posix()),
            "key={}".format(json_digest(_wanted_stamp(target)))]


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--cache-outputs" or sys.argv[2] not in TARGETS:
        raise SystemExit("usage: resvg_library.py --cache-outputs <{}>".format("|".join(TARGETS)))
    print("\n".join(cache_outputs(sys.argv[2])))
