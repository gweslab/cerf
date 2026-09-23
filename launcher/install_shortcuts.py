from __future__ import annotations

import ctypes
import shutil
from ctypes import wintypes
from pathlib import Path
from typing import Optional

from branding import PRODUCT_NAME
from upgrade_process import UNINSTALL_FLAG, launcher_exe_in

UNINSTALL_NAME = "Uninstall " + PRODUCT_NAME
UNINSTALL_ICON_INDEX = 1

_CLSID_SHELL_LINK = "{00021401-0000-0000-C000-000000000046}"
_IID_ISHELLLINKW = "{000214F9-0000-0000-C000-000000000046}"
_IID_IPERSISTFILE = "{0000010B-0000-0000-C000-000000000046}"

_SLOT_QUERY_INTERFACE = 0
_SLOT_RELEASE = 2
_SLOT_SET_DESCRIPTION = 7
_SLOT_SET_WORKING_DIRECTORY = 9
_SLOT_SET_ARGUMENTS = 11
_SLOT_SET_ICON_LOCATION = 17
_SLOT_SET_PATH = 20
_SLOT_PERSIST_FILE_SAVE = 6

_CLSCTX_INPROC_SERVER = 1
_CSIDL_PROGRAMS = 0x0002
_CSIDL_DESKTOPDIRECTORY = 0x0010
_SHGFP_TYPE_CURRENT = 0
_MAX_PATH = 260

_S_OK = 0
_S_FALSE = 1

_HRESULT = ctypes.c_long


class _Guid(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_byte * 8)]


class ShortcutError(OSError):
    pass


def _guid(text: str) -> _Guid:
    out = _Guid()
    if ctypes.windll.ole32.CLSIDFromString(wintypes.LPCWSTR(text),
                                           ctypes.byref(out)) != _S_OK:
        raise ShortcutError("CLSIDFromString failed for " + text)
    return out


def _method(interface: ctypes.c_void_p, slot: int, *argtypes):
    vtable = ctypes.cast(
        interface, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    proto = ctypes.WINFUNCTYPE(_HRESULT, ctypes.c_void_p, *argtypes)
    return proto(vtable[slot])


def _set_string(interface: ctypes.c_void_p, slot: int, value: str) -> None:
    _method(interface, slot, wintypes.LPCWSTR)(interface, value)


def _release(interface: ctypes.c_void_p) -> None:
    vtable = ctypes.cast(
        interface, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    proto = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
    proto(vtable[_SLOT_RELEASE])(interface)


def known_folder(csidl: int) -> Optional[Path]:
    buf = ctypes.create_unicode_buffer(_MAX_PATH)
    shell32 = ctypes.windll.shell32
    shell32.SHGetFolderPathW.argtypes = [wintypes.HWND, ctypes.c_int,
                                         wintypes.HANDLE, wintypes.DWORD,
                                         wintypes.LPWSTR]
    if shell32.SHGetFolderPathW(None, csidl, None,
                                _SHGFP_TYPE_CURRENT, buf) != _S_OK:
        return None
    return Path(buf.value) if buf.value else None


def desktop_dir() -> Optional[Path]:
    return known_folder(_CSIDL_DESKTOPDIRECTORY)


def start_menu_dir() -> Optional[Path]:
    programs = known_folder(_CSIDL_PROGRAMS)
    return None if programs is None else programs / PRODUCT_NAME


def _build_link(link: ctypes.c_void_p, target: Path, arguments: str,
                description: str, icon: Optional[Path],
                icon_index: int) -> None:
    _set_string(link, _SLOT_SET_PATH, str(target))
    _set_string(link, _SLOT_SET_WORKING_DIRECTORY, str(target.parent))
    if arguments:
        _set_string(link, _SLOT_SET_ARGUMENTS, arguments)
    if description:
        _set_string(link, _SLOT_SET_DESCRIPTION, description)
    if icon is not None:
        _method(link, _SLOT_SET_ICON_LOCATION, wintypes.LPCWSTR,
                ctypes.c_int)(link, str(icon), icon_index)


def write_shortcut(path: Path, target: Path, arguments: str = "",
                   description: str = "", icon: Optional[Path] = None,
                   icon_index: int = 0) -> None:
    ole32 = ctypes.windll.ole32
    initialized = ole32.CoInitialize(None) in (_S_OK, _S_FALSE)
    link = ctypes.c_void_p()
    persist = ctypes.c_void_p()
    try:
        if ole32.CoCreateInstance(ctypes.byref(_guid(_CLSID_SHELL_LINK)), None,
                                  _CLSCTX_INPROC_SERVER,
                                  ctypes.byref(_guid(_IID_ISHELLLINKW)),
                                  ctypes.byref(link)) != _S_OK:
            raise ShortcutError("no shell-link object for " + str(path))

        _build_link(link, target, arguments, description, icon, icon_index)

        query = _method(link, _SLOT_QUERY_INTERFACE, ctypes.POINTER(_Guid),
                        ctypes.POINTER(ctypes.c_void_p))
        if query(link, ctypes.byref(_guid(_IID_IPERSISTFILE)),
                 ctypes.byref(persist)) != _S_OK:
            raise ShortcutError("no IPersistFile for " + str(path))

        path.parent.mkdir(parents=True, exist_ok=True)
        save = _method(persist, _SLOT_PERSIST_FILE_SAVE, wintypes.LPCWSTR,
                       wintypes.BOOL)
        if save(persist, str(path), True) != _S_OK:
            raise ShortcutError("cannot write " + str(path))
    finally:
        if persist:
            _release(persist)
        if link:
            _release(link)
        if initialized:
            ole32.CoUninitialize()


def desktop_shortcut_path() -> Optional[Path]:
    desktop = desktop_dir()
    return None if desktop is None else desktop / (PRODUCT_NAME + ".lnk")


def create_desktop_shortcut(install_dir: Path) -> Optional[Path]:
    path = desktop_shortcut_path()
    if path is None:
        raise ShortcutError("the desktop folder could not be located")
    write_shortcut(path, launcher_exe_in(install_dir),
                   description=PRODUCT_NAME)
    return path


def create_start_menu_entries(install_dir: Path) -> Optional[Path]:
    folder = start_menu_dir()
    if folder is None:
        raise ShortcutError("the Start menu folder could not be located")
    launcher = launcher_exe_in(install_dir)
    write_shortcut(folder / (PRODUCT_NAME + ".lnk"), launcher,
                   description=PRODUCT_NAME)
    write_shortcut(folder / (UNINSTALL_NAME + ".lnk"), launcher,
                   arguments=UNINSTALL_FLAG, description=UNINSTALL_NAME,
                   icon=launcher, icon_index=UNINSTALL_ICON_INDEX)
    return folder


def remove_desktop_shortcut() -> None:
    path = desktop_shortcut_path()
    if path is not None and path.is_file():
        path.unlink()


def remove_start_menu_entries() -> None:
    folder = start_menu_dir()
    if folder is not None and folder.is_dir():
        shutil.rmtree(folder)
