from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable, Dict, List

import rust_library_build
from json_files import json_digest, read_json_or_none, write_json
from rust_library_build import TARGETS, RustTarget
from tool_log import tagged
from verified_download import fetch_verified

RESVG_VERSION = "0.48.1"
ARCHIVE = "resvg-{}.tar.xz".format(RESVG_VERSION)
ARCHIVE_SHA256 = "13ed5a2bae7a01156288ecae5bf944cf7d1c572742c19fc68027947a4d87294c"
ARCHIVE_URL = "https://github.com/linebender/resvg/releases/download/v{}/{}".format(RESVG_VERSION, ARCHIVE)
RESVG_DIR = Path("third_party") / "resvg"
STAMP_NAME = "cerf_resvg.json"
LINK_LIBRARIES = "link_libraries.txt"
NATIVE_LIBS_NOTE = "note: native-static-libs:"


say = tagged("RESVG")


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
    rust = rust_library_build.toolchain(root, target, heartbeat)
    archive = fetch_verified(ARCHIVE_URL, root / RESVG_DIR / "downloads" / ARCHIVE, ARCHIVE_SHA256, say)
    rust_library_build.unpack(archive, source, "resvg-{}".format(RESVG_VERSION))
    heartbeat()
    target_dir = base / "target"
    argv = rust_library_build.cargo_argv(rust, target, "rustc")
    argv += ["--manifest-path", str(source / "crates" / "c-api" / "Cargo.toml"), "--lib",
             "--crate-type", "staticlib", "--release", "--locked", "--target", target.triple,
             "--target-dir", str(target_dir), "--", "--print", "native-static-libs"]
    say("Building resvg {} for {}".format(RESVG_VERSION, target.triple))
    notes: List[str] = []

    def keep_note(line: str) -> None:
        if NATIVE_LIBS_NOTE in line:
            notes.append(line.split(NATIVE_LIBS_NOTE, 1)[1])

    rust_library_build.run_cargo(argv, rust.environment(env), "cargo rustc for resvg {}".format(target.triple),
                                 keep_note)
    heartbeat()
    if not notes:
        raise rust_library_build.RustBuildError("resvg: rustc printed no native-static-libs line")
    built = target_dir / target.triple / "release" / _library_name(target.triple)
    if prefix.exists():
        shutil.rmtree(str(prefix))
    (prefix / "include").mkdir(parents=True)
    (prefix / "lib").mkdir()
    shutil.copy2(str(source / "crates" / "c-api" / "resvg.h"), str(prefix / "include" / "resvg.h"))
    shutil.copy2(str(built), str(prefix / "lib" / built.name))
    (prefix / LINK_LIBRARIES).write_text("\n".join(_link_libraries(notes[-1])) + "\n", encoding="utf-8")
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
