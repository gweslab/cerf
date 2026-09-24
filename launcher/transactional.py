from __future__ import annotations

import ctypes
import json
import sys
import tkinter as tk
from ctypes import wintypes
from pathlib import Path
from typing import List

from app_paths import resolve_devices_dir, resolve_icon
from device_state import write_cerf_json
from screen_geometry import screen_work_area
from transactional_about import run_about
from transactional_live_customizations import run_live_customizations
from transactional_settings import run_settings
from ui_dialogs import show_error
import ui_theme as theme

TRANSACTIONAL_COMMAND = "transactional"

_SCAFFOLDINGS = {
    "about": run_about,
    "live_customizations": run_live_customizations,
    "settings": run_settings,
}


class TransactionalContext:
    def __init__(self, root: tk.Tk, device_dir: Path, owner_hwnd: int = 0):
        self.root = root
        self.device_dir = device_dir
        self.owner_hwnd = owner_hwnd


def _return_foreground(owner_hwnd: int) -> None:
    if sys.platform != "win32" or not owner_hwnd:
        return
    try:
        user32 = ctypes.windll.user32
        pid = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(wintypes.HWND(owner_hwnd),
                                        ctypes.byref(pid))
        if pid.value:
            user32.AllowSetForegroundWindow(pid.value)
        user32.SetForegroundWindow(wintypes.HWND(owner_hwnd))
    except (OSError, AttributeError):
        pass


def _make_root() -> tk.Tk:
    root = tk.Tk()
    theme.apply_theme(root)
    root.withdraw()
    icon = resolve_icon()
    if icon is not None:
        try:
            root.iconbitmap(default=str(icon))
        except tk.TclError:
            pass
    wa_x, wa_y, wa_w, wa_h = screen_work_area(root)
    root.geometry("1x1+{}+{}".format(wa_x + wa_w // 2, wa_y + wa_h // 2))
    root.update_idletasks()
    return root


def run_transactional(argv: List[str]) -> int:
    if len(argv) < 2:
        return 2
    device_name, file_name = argv[0], argv[1]
    owner_hwnd = 0
    if len(argv) >= 3:
        try:
            owner_hwnd = int(argv[2], 10)
        except ValueError:
            owner_hwnd = 0
    device_dir = resolve_devices_dir() / device_name
    path = device_dir / file_name

    try:
        with path.open("r", encoding="utf-8") as f:
            request = json.load(f)
    except (OSError, ValueError):
        return 2
    if not isinstance(request, dict) or not request:
        return 2

    root = _make_root()
    ctx = TransactionalContext(root, device_dir, owner_hwnd)
    answered = False
    try:
        for key in list(request.keys()):
            block = request[key]
            if not isinstance(block, dict):
                continue
            scaffolding = _SCAFFOLDINGS.get(key)
            if scaffolding is None:
                show_error(root, "Unsupported request",
                           "This CERF build asked the launcher for "
                           "\"{}\", which this launcher does not "
                           "provide.".format(key))
                continue
            query = block.get("query")
            response = scaffolding(ctx, query if isinstance(query, dict) else {})
            if response is not None:
                block["response"] = response
                answered = True
    finally:
        _return_foreground(owner_hwnd)
        root.destroy()

    if answered:
        try:
            write_cerf_json(path, request)
        except OSError:
            return 2
    return 0
