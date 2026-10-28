from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

import build_report
import local_config
import resvg_library
import verified_download
from host_branch import HostBranch
from tool_process import exit_code, failure_text


class BuildAbort(Exception):
    def __init__(self, reason: object) -> None:
        super().__init__("[BUILD] FAILED! {}".format(reason))


class FrontendBuild:
    device_traces = True

    def __init__(self, root: Path, config: str, mode: str, rebuild: bool,
                 heartbeat: Callable[[], None], branch: HostBranch) -> None:
        self.root = root
        self.config = config
        self.mode = mode
        self.rebuild = rebuild
        self.heartbeat = heartbeat
        self.branch = branch

    @property
    def dev(self) -> str:
        return "OFF" if self.mode == "production" else "ON"

    def cmake_options(self) -> List[str]:
        return ["-DCERF_BUILD_QT=ON", "-DCERFCORE_DEV_MODE=" + self.dev,
                "-DCERFCORE_DEVICE_TRACES=" + (self.dev if self.device_traces else "OFF"),
                "-DCERFQT_LOCAL_CONFIG_NAME=" + local_config.NAME,
                "-DPython3_EXECUTABLE={}".format(sys.executable)]

    def compiler_cache(self) -> Optional[str]:
        return shutil.which("ccache")

    def compiler_cache_options(self) -> List[str]:
        ccache = self.compiler_cache()
        return [] if ccache is None else ["-DCMAKE_CXX_COMPILER_LAUNCHER=" + ccache]

    def resvg_options(self, env: Dict[str, str]) -> List[str]:
        try:
            return resvg_library.cmake_options(self.root, self.branch.name, env, self.heartbeat)
        except (resvg_library.ResvgError, verified_download.DownloadError, OSError) as exc:
            raise BuildAbort(exc)

    def build_dir(self, config: Optional[str]) -> Path:
        name = "cmake-" + self.branch.name
        return self.root / "build" / (name if config is None else "{}-{}".format(name, config.lower()))

    def clear_for_rebuild(self, build_dir: Path) -> None:
        if self.rebuild and build_dir.exists():
            shutil.rmtree(str(build_dir))

    def configure(self, build_dir: Path, argv: List[object], env: Optional[Dict[str, str]] = None) -> None:
        print("[LIBS] libCerfEngine, libCerfCore, cerf-qt ({}, {})".format(self.branch.name, self.config),
              flush=True)
        code = exit_code(argv, env=env)
        self.heartbeat()
        if code != 0:
            raise BuildAbort(failure_text("CMake configure of {}".format(build_dir), code))

    def compile(self, argv: List[object], env: Optional[Dict[str, str]] = None) -> bool:
        code = exit_code(argv, env=env)
        self.heartbeat()
        if code != 0:
            build_report.build_exit_failed(self.branch.frontend, code)
            return False
        return True
