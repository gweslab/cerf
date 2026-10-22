from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional

import host_branch
from app_paths import FRONTEND_NAME, frontend_executable_in, launcher_executable_in
from child_process import spawn_detached

ROOT_LAUNCHER_NAME = host_branch.current().forwarder
UPGRADE_DIR_NAME = "upgrade"
UPGRADE_ZIP_NAME = "upgrade.zip"
GLOBAL_CONFIG_NAME = "cerf.json"
PID_WAIT_TIMEOUT = 30.0

INSTALL_FLAG = "--upgrade"
FRESH_INSTALL_FLAG = "--install"
POST_UPGRADE_FLAG = "--post-upgrade"
UNINSTALL_FLAG = "--uninstall"
UNINSTALL_DIR_PREFIX = "--uninstall-dir="
DESKTOP_ICON_FLAG = "--create-desktop-icon"
START_MENU_FLAG = "--create-start-menu-entry"
NO_LAUNCH_FLAG = "--do-not-launch-after-install"
WAIT_FOR_PID_PREFIX = "--wait-for-pid="

class UpgradeError(RuntimeError):
    pass


def _same_directory(a: str, b: Path) -> bool:
    return (os.path.normcase(os.path.abspath(a))
            == os.path.normcase(os.path.abspath(str(b))))


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _TH32CS_SNAPPROCESS = 0x00000002
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    _SYNCHRONIZE = 0x00100000
    _WAIT_TIMEOUT = 0x00000102
    _ERROR_ACCESS_DENIED = 5
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    def _image_path(pid: int) -> Optional[str]:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False,
                                      wintypes.DWORD(pid))
        if not handle:
            return None
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer,
                                                       ctypes.byref(size)):
                return None
            return buffer.value
        finally:
            kernel32.CloseHandle(handle)

    def running_cerf_pids(install_dir: Path) -> List[int]:
        kernel32 = ctypes.windll.kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if snapshot == _INVALID_HANDLE_VALUE:
            raise UpgradeError("cannot enumerate running processes")
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
        pids: List[int] = []
        try:
            if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                return pids
            while True:
                if entry.szExeFile.lower() == FRONTEND_NAME:
                    pid = int(entry.th32ProcessID)
                    image = _image_path(pid)
                    if image is None or _same_directory(
                            os.path.dirname(image), frontend_executable_in(install_dir).parent):
                        pids.append(pid)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    return pids
        finally:
            kernel32.CloseHandle(snapshot)

    def _pid_alive(pid: int) -> bool:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(_SYNCHRONIZE, False, wintypes.DWORD(pid))
        if not handle:
            return kernel32.GetLastError() == _ERROR_ACCESS_DENIED
        try:
            return kernel32.WaitForSingleObject(handle, 0) == _WAIT_TIMEOUT
        finally:
            kernel32.CloseHandle(handle)
else:
    from host_processes import executable_path, is_alive, list_processes

    def running_cerf_pids(install_dir: Path) -> List[int]:
        pids: List[int] = []
        for pid, name in list_processes().items():
            if name != FRONTEND_NAME:
                continue
            image = executable_path(pid)
            if image is None or _same_directory(os.path.dirname(image),
                                                frontend_executable_in(install_dir).parent):
                pids.append(pid)
        return pids

    def _pid_alive(pid: int) -> bool:
        return is_alive(pid)


def wait_for_cerf_exit(ask_retry: Callable[[str, str], bool],
                       install_dir: Path) -> bool:
    while True:
        if not running_cerf_pids(install_dir):
            return True
        if not ask_retry(
                "The emulator is running",
                "CE Runtime Foundation is running and its files cannot be "
                "replaced while it is.\n\nClose every emulator window, then "
                "retry."):
            return False


def wait_for_pid_exit(pid: int, timeout: float = PID_WAIT_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while _pid_alive(pid):
        if time.monotonic() >= deadline:
            raise UpgradeError(
                f"the previous CERF launcher (pid {pid}) is still running after "
                f"{int(timeout)}s; its files cannot be replaced")
        time.sleep(0.05)


def launcher_exe_in(directory: Path) -> Path:
    candidate = launcher_executable_in(directory)
    if candidate.is_file() or ROOT_LAUNCHER_NAME is None:
        return candidate
    return directory / ROOT_LAUNCHER_NAME


def spawn_stage(exe: Path, args: List[str], cwd: Path) -> None:
    try:
        spawn_detached([str(exe)] + args, cwd)
    except OSError as exc:
        raise UpgradeError(f"cannot start {exe}: {exc}") from exc


def stage_argument(wait_pid: int, mode_flag: str,
                   carried: Optional[List[str]] = None) -> List[str]:
    return [f"--wait-for-pid={wait_pid}", mode_flag] + list(carried or [])


def find_pid_argument(argv: List[str], prefix: str) -> Optional[int]:
    for arg in argv:
        if arg.startswith(prefix):
            value = arg[len(prefix):]
            if value.isdigit():
                return int(value)
    return None
