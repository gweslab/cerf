from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Dict, List

import build_report
import qt_windows
import vcpkg_install
import verified_download
import vs_toolchain
import windows_deploy
from frontend_build import BuildAbort, FrontendBuild
from host_branch import output_dir
from tool_process import output_or_raise, prepend_path

GENERATOR_KEYS = ("CMAKE_GENERATOR", "CMAKE_GENERATOR_PLATFORM", "CMAKE_GENERATOR_TOOLSET",
                  "CMAKE_GENERATOR_INSTANCE")


def check_vcpkg_integration() -> None:
    if not vcpkg_install.integration_props().is_file():
        raise BuildAbort(
            "vcpkg MSBuild integration missing. Run 'vcpkg integrate install' "
            "from the vcpkg that ships with Visual Studio (path is "
            "'<VS install>\\VC\\vcpkg\\vcpkg.exe' inside the VS install -- comes with the C++ "
            "desktop workload).")


class _MsvcBuild(FrontendBuild):
    toolchain = None

    def discover(self) -> None:
        try:
            tc = vs_toolchain.require(self.branch.frontend)
        except vs_toolchain.ToolchainError as exc:
            raise BuildAbort(exc)
        print("[BUILD] {}, MSVC toolset {} ({}) (installed: {})".format(
            tc.instance.get("displayName", "?"), tc.tools_version, tc.platform_toolset,
            "; ".join(tc.installed)), flush=True)
        self.toolchain = tc

    def _generator(self) -> str:
        cmake = self.toolchain.cmake
        major = self.toolchain.instance["installationVersion"].split(".")[0]
        caps = output_or_raise([cmake, "-E", "capabilities"], BuildAbort)
        names = [g.get("name", "") for g in json.loads(caps).get("generators", [])]
        pattern = re.compile(r"^Visual Studio {} \d{{4}}$".format(major))
        match = next((n for n in names if pattern.match(n)), None)
        if match is None:
            raise BuildAbort("{} has no generator for Visual Studio {}."
                             .format(cmake, major))
        return match

    def _vcpkg(self) -> Path:
        env = prepend_path(dict(os.environ), self.toolchain.cmake.parent)
        try:
            return vcpkg_install.install(self.root, vcpkg_install.vcpkg_root(self.branch.name),
                                         vcpkg_install.TRIPLETS[self.branch.name], env, self.heartbeat)
        except (vcpkg_install.VcpkgError, OSError) as exc:
            raise BuildAbort(exc)

    def _configure(self, build_dir: Path, options: List[str]) -> None:
        generator = self._generator()
        tc = self.toolchain
        self.clear_for_rebuild(build_dir)
        wanted: Dict[str, str] = {
            "CMAKE_GENERATOR": generator,
            "CMAKE_GENERATOR_PLATFORM": "Win32",
            "CMAKE_GENERATOR_TOOLSET": "{},version={}".format(tc.platform_toolset,
                                                              tc.tools_version),
            "CMAKE_GENERATOR_INSTANCE": tc.instance["installationPath"],
        }
        cache = build_dir / "CMakeCache.txt"
        if cache.is_file():
            cached = {}
            for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^(CMAKE_GENERATOR(?:_PLATFORM|_TOOLSET|_INSTANCE)?):[A-Z]+=(.*)$",
                             line)
                if m:
                    cached[m.group(1)] = m.group(2)
            changed = [k for k in GENERATOR_KEYS if cached.get(k) != wanted[k]]
            if changed:
                print("[CMAKE] {} changed; configuring {} from scratch".format(
                    ", ".join(changed), build_dir), flush=True)
                shutil.rmtree(build_dir)
        self.configure(build_dir, [tc.cmake, "-S", self.root, "-B", build_dir, "-G", generator, "-A", "Win32",
                                   "-T", wanted["CMAKE_GENERATOR_TOOLSET"],
                                   "-DCMAKE_GENERATOR_INSTANCE={}".format(wanted["CMAKE_GENERATOR_INSTANCE"]),
                                   "-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded"]
                       + self.cmake_options() + options)


class WindowsBuild(_MsvcBuild):
    def build(self) -> bool:
        installed = self._vcpkg()
        try:
            qt_prefix = qt_windows.ensure(self.root, self.toolchain, self.heartbeat)
        except (qt_windows.QtBuildError, verified_download.DownloadError, OSError) as exc:
            raise BuildAbort("Qt: {}".format(exc))
        resvg = self.resvg_options(dict(os.environ))
        out_dirs =["-DCMAKE_RUNTIME_OUTPUT_DIRECTORY_{}={}".format(
            config.upper(), output_dir(self.root, config, self.branch))
            for config in ("Release", "Debug")]
        build_dir = self.build_dir(None)
        self._configure(build_dir, [
            "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
            "-DCMAKE_MAP_IMPORTED_CONFIG_DEBUG=Release",
            "-DCMAKE_PREFIX_PATH={};{}".format(qt_prefix, installed)] + resvg + out_dirs)
        if not self.compile([self.toolchain.cmake, "--build", build_dir, "--config", self.config,
                             "--parallel", "--", "/v:minimal", "/nologo", "/nodeReuse:false"]):
            return False
        exe = output_dir(self.root, self.config, self.branch) / self.branch.frontend
        if not build_report.built_file_present(exe.name, exe, "binary"):
            return False
        build_report.built_file(exe.name, exe.resolve())
        try:
            windows_deploy.deploy(self.root, exe, qt_prefix, self.toolchain)
        except (windows_deploy.DeployError, OSError) as exc:
            build_report.deploy_failed(exc)
            return False
        self.heartbeat()
        return True
