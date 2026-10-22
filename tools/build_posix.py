from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Callable, List, Optional

import homebrew_packages
import macos_deploy
from host_branch import HostBranch, output_dir


class BuildAbort(Exception):
    pass


def _run(argv: List[str]) -> int:
    return subprocess.run([str(a) for a in argv], check=False).returncode


def _homebrew_prefix() -> str:
    brew = shutil.which("brew")
    if brew is None:
        raise BuildAbort("[BUILD] FAILED! brew not found on PATH. Install Homebrew, then "
                         "{}.".format(homebrew_packages.install_command()))
    result = subprocess.run([brew, "--prefix"], capture_output=True, text=True, check=False)
    prefix = result.stdout.strip()
    if result.returncode != 0 or not prefix:
        raise BuildAbort("[BUILD] FAILED! brew --prefix returned {}".format(result.returncode))
    return prefix


class PosixBuild:
    def __init__(self, root: Path, config: str, mode: str, rebuild: bool,
                 heartbeat: Callable[[], None], branch: HostBranch) -> None:
        self.root = root
        self.config = config
        self.mode = mode
        self.rebuild = rebuild
        self.heartbeat = heartbeat
        self.branch = branch
        self.compiler = "clang++" if sys.platform == "darwin" else "g++"
        self.cmake: Optional[str] = None
        self.ccache: Optional[str] = None
        self.prefix_path: Optional[str] = None

    def discover(self) -> None:
        missing = [tool for tool in ("cmake", "ninja", self.compiler) if shutil.which(tool) is None]
        if missing:
            raise BuildAbort("[BUILD] FAILED! {} not found on PATH. Install CMake, Ninja, a C++ "
                             "compiler and the Qt 6 development packages.".format(", ".join(missing)))
        self.cmake = shutil.which("cmake")
        self.ccache = shutil.which("ccache")
        if sys.platform == "darwin":
            self.prefix_path = _homebrew_prefix()
        print("[BUILD] cmake {}, ninja {}, {} {}{}{}".format(
            self.cmake, shutil.which("ninja"), self.compiler, shutil.which(self.compiler),
            ", ccache {}".format(self.ccache) if self.ccache else "",
            ", prefix {}".format(self.prefix_path) if self.prefix_path else ""), flush=True)

    def build(self) -> bool:
        cmake_dir = self.root / "build" / "cmake-{}-{}".format(self.branch.name,
                                                               self.config.lower())
        out = output_dir(self.root, self.config, self.branch)
        dev = "OFF" if self.mode == "production" else "ON"
        if self.rebuild and cmake_dir.exists():
            shutil.rmtree(cmake_dir)
        configure = [self.cmake, "-S", self.root, "-B", cmake_dir, "-G", "Ninja",
                     "-DCMAKE_BUILD_TYPE=" + self.config, "-DCMAKE_CXX_COMPILER=" + self.compiler,
                     "-DCERF_BUILD_QT=ON", "-DCERFCORE_DEV_MODE=" + dev,
                     "-DCERFCORE_DEVICE_TRACES=" + dev,
                     "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={}".format(out),
                     "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
        if self.prefix_path:
            configure.append("-DCMAKE_PREFIX_PATH=" + self.prefix_path)
        if self.ccache:
            configure.append("-DCMAKE_CXX_COMPILER_LAUNCHER=" + self.ccache)
        print("[LIBS] libCerfEngine, libCerfCore, libCerfFrontend, cerf-qt ({})".format(
            self.config), flush=True)
        code = _run(configure)
        self.heartbeat()
        if code != 0:
            raise BuildAbort("[BUILD] CMake configure FAILED (exit={})".format(code))
        code = _run([self.cmake, "--build", cmake_dir, "--parallel"])
        self.heartbeat()
        frontend = PurePosixPath(self.branch.frontend)
        exe = out.joinpath(*frontend.parts)
        if code != 0:
            print("[BUILD] {} FAILED (cmake --build exit={})".format(self.branch.frontend, code),
                  flush=True)
            return False
        if not exe.is_file():
            print("[BUILD] {} FAILED (the build reported success but the binary is not at {})"
                  .format(self.branch.frontend, exe), flush=True)
            return False
        if sys.platform == "darwin":
            print("[DEPLOY] {}".format(frontend.parts[0]), flush=True)
            try:
                macos_deploy.deploy(out / frontend.parts[0], self.prefix_path)
            except (macos_deploy.DeployError, OSError) as exc:
                print("[DEPLOY] FAILED! {}".format(exc), flush=True)
                return False
            self.heartbeat()
        stat = exe.stat()
        print("[BUILD] {} OK: {}".format(self.branch.frontend, exe), flush=True)
        print("[BUILD] Size: {} bytes".format(stat.st_size), flush=True)
        print("[BUILD] Time: {}".format(datetime.fromtimestamp(stat.st_mtime)), flush=True)
        return True
