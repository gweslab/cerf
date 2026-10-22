from __future__ import annotations

import os
import sys

from app_paths import FRONTEND_NAME
from device_state import RunningStatus

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.windll.user32

    SW_RESTORE = 9

    def _belongs_to_pid(hwnd: int, pid: int) -> bool:
        out = wintypes.DWORD(0)
        _user32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(out))
        return out.value == pid

    def show_running_window(status: RunningStatus) -> bool:
        hwnd = status.hwnd
        if not hwnd or not _user32.IsWindow(wintypes.HWND(hwnd)):
            return False
        if status.pid and not _belongs_to_pid(hwnd, status.pid):
            return False
        _user32.ShowWindow(wintypes.HWND(hwnd), SW_RESTORE)
        _user32.SetForegroundWindow(wintypes.HWND(hwnd))
        return True
else:
    import socket

    from host_processes import process_name

    def _show_address(pid: int):
        if sys.platform == "darwin":
            directory = os.environ.get("TMPDIR") or "/tmp/"
            if not directory.endswith("/"):
                directory += "/"
            return "{}cerf-show-{}".format(directory, pid)
        return b"\0" + "cerf-show/{}".format(pid).encode("ascii")

    def show_running_window(status: RunningStatus) -> bool:
        if not status.pid or process_name(status.pid) != FRONTEND_NAME:
            return False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
                s.sendto(b"show", _show_address(status.pid))
        except OSError:
            return False
        return True
