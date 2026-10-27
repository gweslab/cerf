from __future__ import annotations

import os
import shutil
import sys
from pathlib import PurePosixPath
from typing import Optional

import build_report
import homebrew_packages
import macos_deploy
from frontend_build import BuildAbort, FrontendBuild
from host_branch import output_dir
from product_facts import QML_SOURCE_DIR
from tool_process import output_or_raise


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
    ccache: Optional[str] = None
    prefix_path: Optional[str] = None

    def discover(self) -> None:
        missing = [tool for tool in BUILD_TOOLS if shutil.which(tool) is None]
        if missing:
            raise BuildAbort("{} not found on PATH. Install CMake, Ninja, a C++ "
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
        cmake_dir = self.build_dir(self.config)
        out = output_dir(self.root, self.config, self.branch)
        self.clear_for_rebuild(cmake_dir)
        resvg = self.resvg_options(dict(os.environ))
        configure = [self.cmake, "-S", self.root, "-B", cmake_dir, "-G", "Ninja",
                     "-DCMAKE_BUILD_TYPE=" + self.config, "-DCMAKE_CXX_COMPILER=" + self.compiler,
                     "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={}".format(out),
                     "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"] + self.cmake_options() + resvg
        if self.prefix_path:
            configure.append("-DCMAKE_PREFIX_PATH=" + self.prefix_path)
        if self.ccache:
            configure.append("-DCMAKE_CXX_COMPILER_LAUNCHER=" + self.ccache)
        self.configure(cmake_dir, configure)
        if not self.compile([self.cmake, "--build", cmake_dir, "--parallel"]):
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
