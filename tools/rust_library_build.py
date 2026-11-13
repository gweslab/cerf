from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List

import android_sdk
import rust_toolchain
import tar_archives
from host_branch import ANDROID_AMD64, ANDROID_ARM64, LINUX_AMD64, LINUX_ARM64, MACOS_ARM64, WIN32_X86
from tool_process import failure_text


@dataclass(frozen=True)
class RustTarget:
    triple: str
    toolchain: str
    build_std: bool


TARGETS = {
    WIN32_X86: RustTarget("i686-win7-windows-msvc", rust_toolchain.NIGHTLY, True),
    LINUX_AMD64: RustTarget("x86_64-unknown-linux-gnu", rust_toolchain.STABLE, False),
    LINUX_ARM64: RustTarget("aarch64-unknown-linux-gnu", rust_toolchain.STABLE, False),
    MACOS_ARM64: RustTarget("aarch64-apple-darwin", rust_toolchain.STABLE, False),
    ANDROID_ARM64: RustTarget("aarch64-linux-android", rust_toolchain.STABLE, False),
    ANDROID_AMD64: RustTarget("x86_64-linux-android", rust_toolchain.STABLE, False),
}

NDK_HOST_TAGS = {"win32": "windows-x86_64", "linux": "linux-x86_64", "darwin": "darwin-x86_64"}


class RustBuildError(Exception):
    pass


def unpack(archive: Path, source: Path, top_dir: str) -> None:
    if (source / "Cargo.lock").is_file():
        return
    if source.exists():
        shutil.rmtree(str(source))
    staging = source.with_name(source.name + ".unpack")
    if staging.exists():
        shutil.rmtree(str(staging))
    staging.mkdir(parents=True)
    tar_archives.extract(archive, staging)
    (staging / top_dir).replace(source)
    staging.rmdir()


def toolchain(root: Path, target: RustTarget, heartbeat: Callable[[], None]) -> rust_toolchain.RustToolchain:
    rust = rust_toolchain.RustToolchain(root, heartbeat)
    try:
        if target.build_std:
            rust.ensure(target.toolchain, [], ["rust-src"])
        else:
            rust.ensure(target.toolchain, [target.triple], [])
    except rust_toolchain.RustError as exc:
        raise RustBuildError(str(exc))
    return rust


def cargo_argv(rust: rust_toolchain.RustToolchain, target: RustTarget, subcommand: str) -> List[str]:
    argv = [str(rust.cargo()), "+" + target.toolchain, subcommand]
    if target.build_std:
        argv += ["-Z", "build-std=std,panic_abort"]
    return argv


def _env_triple(triple: str) -> str:
    return triple.replace("-", "_")


def _ndk_tool(bin_dir: Path, name: str) -> str:
    executable = bin_dir / (name + ".exe" if sys.platform == "win32" else name)
    if not executable.is_file():
        raise RustBuildError("{} does not exist; the Android NDK at {} is incomplete".format(executable, bin_dir))
    return str(executable)


def android_environment(triple: str, env: Dict[str, str]) -> Dict[str, str]:
    ndk = env.get("ANDROID_NDK_HOME")
    if not ndk:
        raise RustBuildError("ANDROID_NDK_HOME is not set for the {} build".format(triple))
    bin_dir = Path(ndk) / "toolchains" / "llvm" / "prebuilt" / NDK_HOST_TAGS[sys.platform] / "bin"
    clang = _ndk_tool(bin_dir, "clang")
    clangxx = _ndk_tool(bin_dir, "clang++")
    target_flag = "--target={}{}".format(triple, android_sdk.MIN_SDK)
    key = _env_triple(triple)
    out = dict(env)
    out["CC_" + key] = clang
    out["CXX_" + key] = clangxx
    out["AR_" + key] = _ndk_tool(bin_dir, "llvm-ar")
    out["CFLAGS_" + key] = target_flag
    out["CXXFLAGS_" + key] = target_flag
    out["CARGO_TARGET_{}_LINKER".format(key.upper())] = clang
    out["CARGO_TARGET_{}_RUSTFLAGS".format(key.upper())] = "-C link-arg=" + target_flag
    return out


def run_cargo(argv: List[str], env: Dict[str, str], what: str, on_line: Callable[[str], None]) -> None:
    process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, encoding="utf-8", errors="replace")
    for line in process.stdout:
        print(line, end="", flush=True)
        on_line(line)
    code = process.wait()
    if code != 0:
        raise RustBuildError(failure_text(what, code))


def is_android(triple: str) -> bool:
    return triple.endswith("-android")
