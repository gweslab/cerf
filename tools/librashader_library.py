from __future__ import annotations

import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import macos_deploy
import rust_library_build
import rust_toolchain
from host_branch import ANDROID_AMD64, ANDROID_ARM64, LINUX_AMD64, LINUX_ARM64, MACOS_ARM64, WIN32_X86
from json_files import json_digest, read_json_or_none, write_json
from rust_library_build import TARGETS, RustTarget
from tool_log import tagged
from verified_download import fetch_verified, file_sha256

LIBRASHADER_VERSION = "0.12.1"
TAG = "librashader-capi-v{}".format(LIBRASHADER_VERSION)
ARCHIVE = "{}.tar.gz".format(TAG)
ARCHIVE_SHA256 = "2e2d9ff281e4a89830d8d5d2adbdf579cfedb0f457c38fbe9dc3bfcd10a7aa78"
ARCHIVE_URL = "https://github.com/SnowflakePowered/librashader/archive/refs/tags/{}".format(ARCHIVE)
ARCHIVE_TOP_DIR = "librashader-{}".format(TAG)
LIBRASHADER_DIR = Path("third_party") / "librashader"
STAMP_NAME = "cerf_librashader.json"
PROFILE = "optimized"
HEADER = "librashader.h"
LOCK_FILE = "Cargo.lock"
PATCH_DIR = Path(__file__).resolve().parent / "librashader_patch"


@dataclass(frozen=True)
class ModulePatch:
    module_file: str
    crate_dir: str
    anchor_line: str
    module_line: str


PATCHES = (
    ModulePatch("parameter_order.rs", "librashader-preprocess", "mod stage;", "pub mod parameter_order;"),
    ModulePatch("presets_chain.rs", "librashader-capi", "pub mod presets;", "mod presets_chain;"),
)

MPL_CRATES = ("persy", "smartstring")
CRATE_URL = "https://static.crates.io/crates/{0}/{0}-{1}.crate"

RUNTIME_FEATURES = {"gl": "runtime-opengl", "d3d11": "runtime-d3d11", "metal": "runtime-metal"}
RUNTIMES = {
    WIN32_X86: ("gl", "d3d11"),
    LINUX_AMD64: ("gl",),
    LINUX_ARM64: ("gl",),
    MACOS_ARM64: ("metal",),
    ANDROID_ARM64: ("gl",),
    ANDROID_AMD64: ("gl",),
}

say = tagged("LIBRASHADER")


def _built_name(triple: str) -> str:
    if triple.endswith("-msvc"):
        return "librashader_capi.dll"
    if triple.endswith("-apple-darwin"):
        return "liblibrashader_capi.dylib"
    return "liblibrashader_capi.so"


def shipped_name(triple: str, runtime: str) -> str:
    if triple.endswith("-msvc"):
        return "librashader_{}.dll".format(runtime)
    if triple.endswith("-apple-darwin"):
        return "librashader_{}.dylib".format(runtime)
    return "librashader_{}.so".format(runtime)


def _link_args(triple: str, runtime: str) -> List[str]:
    if not triple.endswith("-apple-darwin"):
        return []
    install_name = macos_deploy.FRAMEWORKS_REFERENCE + shipped_name(triple, runtime)
    return ["-C", "link-arg=-Wl,-install_name,{}".format(install_name)]


def _wanted_stamp(branch_name: str, target: RustTarget) -> dict:
    return {"version": LIBRASHADER_VERSION, "toolchain": target.toolchain, "build_std": target.build_std,
            "profile": PROFILE, "runtimes": list(RUNTIMES[branch_name]), "patch": _patch_digest(),
            "link_args": {runtime: _link_args(target.triple, runtime) for runtime in RUNTIMES[branch_name]},
            "prefix_files": [HEADER, LOCK_FILE]}


def _patch_digest() -> Dict[str, str]:
    return {patch.module_file: file_sha256(PATCH_DIR / patch.module_file) for patch in PATCHES}


def _apply_patch(source: Path, patch: ModulePatch) -> None:
    crate = source / patch.crate_dir / "src"
    shutil.copy2(str(PATCH_DIR / patch.module_file), str(crate / patch.module_file))
    lib = crate / "lib.rs"
    declaration = re.compile(r"\s*(pub\s+)?mod\s+{};\s*".format(re.escape(Path(patch.module_file).stem)))
    lines = [line for line in lib.read_text(encoding="utf-8").splitlines() if not declaration.fullmatch(line)]
    if patch.anchor_line not in lines:
        raise rust_library_build.RustBuildError("{} has no '{}' line".format(lib, patch.anchor_line))
    lines.insert(lines.index(patch.anchor_line) + 1, patch.module_line)
    lib.write_text("\n".join(lines) + "\n", encoding="utf-8")


def prefix_dir(root: Path, target: RustTarget) -> Path:
    return root / LIBRASHADER_DIR / LIBRASHADER_VERSION / target.triple


def _build_runtime(rust: rust_toolchain.RustToolchain, target: RustTarget, source: Path, target_dir: Path,
                   runtime: str, env: Dict[str, str]) -> Path:
    argv = rust_library_build.cargo_argv(rust, target, "rustc")
    argv += ["--manifest-path", str(source / "librashader-capi" / "Cargo.toml"), "--lib",
             "--crate-type", "cdylib", "--profile", PROFILE, "--locked", "--no-default-features",
             "--features", RUNTIME_FEATURES[runtime], "--target", target.triple,
             "--target-dir", str(target_dir)]
    link_args = _link_args(target.triple, runtime)
    if link_args:
        argv += ["--"] + link_args
    say("Building librashader {} ({}) for {}".format(LIBRASHADER_VERSION, runtime, target.triple))
    rust_library_build.run_cargo(argv, env, "cargo rustc for librashader {} {}".format(runtime, target.triple),
                                 lambda _line: None)
    return target_dir / target.triple / PROFILE / _built_name(target.triple)


def build(root: Path, branch_name: str, env: Dict[str, str], heartbeat: Callable[[], None]) -> Path:
    target = TARGETS[branch_name]
    base = root / LIBRASHADER_DIR / LIBRASHADER_VERSION
    source = base / "src"
    prefix = prefix_dir(root, target)
    stamp = prefix / STAMP_NAME
    wanted = _wanted_stamp(branch_name, target)
    if read_json_or_none(stamp) == wanted:
        return prefix
    rust = rust_library_build.toolchain(root, target, heartbeat)
    archive = fetch_verified(ARCHIVE_URL, root / LIBRASHADER_DIR / "downloads" / ARCHIVE, ARCHIVE_SHA256, say)
    rust_library_build.unpack(archive, source, ARCHIVE_TOP_DIR)
    for patch in PATCHES:
        _apply_patch(source, patch)
    heartbeat()
    run_env = rust.environment(env)
    if rust_library_build.is_android(target.triple):
        run_env = rust_library_build.android_environment(target.triple, run_env)
    if prefix.exists():
        shutil.rmtree(str(prefix))
    (prefix / "include").mkdir(parents=True)
    (prefix / "lib").mkdir()
    shutil.copy2(str(source / "include" / HEADER), str(prefix / "include" / HEADER))
    shutil.copy2(str(source / LOCK_FILE), str(prefix / LOCK_FILE))
    for runtime in RUNTIMES[branch_name]:
        built = _build_runtime(rust, target, source, base / "target", runtime, run_env)
        heartbeat()
        shutil.copy2(str(built), str(prefix / "lib" / shipped_name(target.triple, runtime)))
    write_json(stamp, wanted)
    say("librashader {} ready in {}".format(LIBRASHADER_VERSION, prefix))
    return prefix


def cmake_options(root: Path, branch_name: str, env: Dict[str, str], heartbeat: Callable[[], None]) -> List[str]:
    prefix = build(root, branch_name, env, heartbeat)
    triple = TARGETS[branch_name].triple
    libraries = [(prefix / "lib" / shipped_name(triple, runtime)).as_posix() for runtime in RUNTIMES[branch_name]]
    return ["-DCERFQT_LIBRASHADER_INCLUDE_DIR={}".format((prefix / "include").as_posix()),
            "-DCERFQT_LIBRASHADER_LIBRARIES={}".format(";".join(libraries))]


def mpl_crate_sources(root: Path, branch_name: str) -> List[Tuple[str, str, str]]:
    lock = (prefix_dir(root, TARGETS[branch_name]) / LOCK_FILE).read_text(encoding="utf-8")
    found = []
    for package in lock.split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(\w+) = "([^"]*)"', package, re.MULTILINE))
        if fields.get("name") in MPL_CRATES:
            found.append((fields["name"], fields["version"], fields["checksum"]))
    if sorted(name for name, _, _ in found) != sorted(MPL_CRATES):
        raise rust_library_build.RustBuildError("Cargo.lock of librashader does not hold each of {}".format(MPL_CRATES))
    return found


def cache_outputs(branch_name: str) -> List[str]:
    target = TARGETS[branch_name]
    prefix = prefix_dir(Path("."), target)
    return ["path={}".format(prefix.as_posix()), "stamp={}".format((prefix / STAMP_NAME).as_posix()),
            "key={}".format(json_digest(_wanted_stamp(branch_name, target)))]


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--cache-outputs" or sys.argv[2] not in TARGETS:
        raise SystemExit("usage: librashader_library.py --cache-outputs <{}>".format("|".join(TARGETS)))
    print("\n".join(cache_outputs(sys.argv[2])))
