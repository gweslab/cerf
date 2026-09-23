from __future__ import annotations

import winreg
from pathlib import Path

from branding import AUTHOR, PRODUCT_NAME
from upgrade_process import (UNINSTALL_FLAG, UPGRADE_DIR_NAME,
                             launcher_exe_in)

KEY_NAME = "CERuntimeFoundation"
UNINSTALL_ROOT = (r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
                  "\\" + KEY_NAME)
HELP_LINK = "https://cerf.cx"


def _directory_kilobytes(path: Path) -> int:
    staged = path / UPGRADE_DIR_NAME
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and staged not in item.parents:
                total += item.stat().st_size
        except OSError:
            continue
    return total // 1024


def register(install_dir: Path, version: str) -> None:
    launcher = launcher_exe_in(install_dir)
    values = [
        ("DisplayName", PRODUCT_NAME),
        ("DisplayIcon", "{},0".format(launcher)),
        ("DisplayVersion", version),
        ("Publisher", AUTHOR),
        ("InstallLocation", str(install_dir)),
        ("UninstallString", '"{}" {}'.format(launcher, UNINSTALL_FLAG)),
        ("HelpLink", HELP_LINK),
    ]
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_ROOT) as key:
        for name, value in values:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD,
                          _directory_kilobytes(install_dir))


def unregister() -> None:
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, UNINSTALL_ROOT)
    except FileNotFoundError:
        pass
