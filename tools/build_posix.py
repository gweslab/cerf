from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path, PurePosixPath
from typing import List, Optional

import appimage_excludelist
import build_report
import homebrew_packages
import macos_deploy
import qt_online_repository
import vcpkg_install
import verified_download
from frontend_build import BuildAbort, FrontendBuild
from host_branch import output_dir
from product_facts import QML_SOURCE_DIR
from tool_process import exit_code, failure_text, output_or_raise


def _homebrew_prefix() -> str:
    brew = shutil.which("brew")
    if brew is None:
        raise BuildAbort("brew not found on PATH. Install Homebrew, then "
                         "{}.".format(homebrew_packages.install_command()))
    return output_or_raise([brew, "--prefix"], BuildAbort).strip()


COMPILER = "clang++" if sys.platform == "darwin" else "g++"
BUILD_TOOLS = ("cmake", "ninja", COMPILER)


class PosixBuild(FrontendBuild):
    compiler = COMPILER
    cmake: Optional[str] = None
    prefix_path: Optional[str] = None

    def discover(self) -> None:
        missing = [tool for tool in BUILD_TOOLS if shutil.which(tool) is None]
        if missing:
            raise BuildAbort("{} not found on PATH. Install CMake, Ninja and a C++ "
                             "compiler.".format(", ".join(missing)))
        self.cmake = shutil.which("cmake")
        if sys.platform == "darwin":
            self.prefix_path = _homebrew_prefix()
        ccache = self.compiler_cache()
        print("[BUILD] cmake {}, ninja {}, {} {}{}{}".format(
            self.cmake, shutil.which("ninja"), self.compiler, shutil.which(self.compiler),
            ", ccache {}".format(ccache) if ccache else "",
            ", prefix {}".format(self.prefix_path) if self.prefix_path else ""), flush=True)

    def _linux_prefix_path(self) -> str:
        try:
            deps = vcpkg_install.install(self.root, vcpkg_install.vcpkg_root(self.branch.name),
                                         vcpkg_install.TRIPLETS[self.branch.name], dict(os.environ), self.heartbeat)
            qt = qt_online_repository.ensure_linux_desktop(self.root, Path(self.cmake), self.heartbeat)
        except (vcpkg_install.VcpkgError, qt_online_repository.QtFetchError, verified_download.DownloadError,
                OSError) as exc:
            raise BuildAbort(exc)
        return "{};{}".format(qt, deps)

    def _deploy_linux(self, cmake_dir: Path, out: Path) -> bool:
        print("[DEPLOY] Qt runtime into {}".format(out), flush=True)
        code = exit_code([self.cmake, "--install", cmake_dir, "--prefix", out])
        self.heartbeat()
        if code != 0:
            build_report.deploy_failed(BuildAbort(failure_text("cmake --install", code)))
            return False
        return True

    def build(self) -> bool:
        cmake_dir = self.build_dir(self.config)
        out = output_dir(self.root, self.config, self.branch)
        self.clear_for_rebuild(cmake_dir)
        if sys.platform.startswith("linux"):
            self.prefix_path = self._linux_prefix_path()
        resvg = self.resvg_options(dict(os.environ))
        configure: List = [self.cmake, "-S", self.root, "-B", cmake_dir, "-G", "Ninja",
                           "-DCMAKE_BUILD_TYPE=" + self.config, "-DCMAKE_CXX_COMPILER=" + self.compiler,
                           "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={}".format(out),
                           "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"] + \
            self.cmake_options() + self.compiler_cache_options() + resvg
        if self.prefix_path:
            configure.append("-DCMAKE_PREFIX_PATH=" + self.prefix_path)
        if sys.platform.startswith("linux"):
            try:
                excludelist = appimage_excludelist.ensure(self.root)
            except (verified_download.DownloadError, OSError) as exc:
                raise BuildAbort(exc)
            configure.append("-DCERFQT_DEPLOY_EXCLUDELIST={}".format(excludelist.as_posix()))
        self.configure(cmake_dir, configure)
        if not self.compile([self.cmake, "--build", cmake_dir, "--parallel"]):
            return False
        if sys.platform.startswith("linux") and not self._deploy_linux(cmake_dir, out):
            return False
        frontend = PurePosixPath(self.branch.frontend)
        exe = out.joinpath(*frontend.parts)
        if not build_report.built_file_present(self.branch.frontend, exe, "binary"):
            return False
        if sys.platform == "darwin":
            print("[DEPLOY] {}".format(frontend.parts[0]), flush=True)
            try:
                macos_deploy.deploy(out / frontend.parts[0], self.prefix_path, self.root / QML_SOURCE_DIR)
            except (macos_deploy.DeployError, OSError) as exc:
                build_report.deploy_failed(exc)
                return False
            self.heartbeat()
        build_report.built_file(self.branch.frontend, exe)
        return True
