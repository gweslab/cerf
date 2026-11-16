from __future__ import annotations

import csv
import io
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, Optional, TypeVar

_T = TypeVar("_T")

_WINDOWS = sys.platform == "win32"
_MACOS = sys.platform == "darwin"

if _MACOS:
    import ctypes
    import ctypes.util

    _RUSAGE_INFO_V2 = 2

    class _RusageInfoV2(ctypes.Structure):
        _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
            (name, ctypes.c_uint64) for name in (
                "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups",
                "ri_pageins", "ri_wired_size", "ri_resident_size", "ri_phys_footprint",
                "ri_proc_start_abstime", "ri_proc_exit_abstime", "ri_child_user_time",
                "ri_child_system_time", "ri_child_pkg_idle_wkups", "ri_child_interrupt_wkups",
                "ri_child_pageins", "ri_child_elapsed_abstime", "ri_diskio_bytesread",
                "ri_diskio_byteswritten")]

    _PROC_PIDPATHINFO_MAXSIZE = 4 * 1024

    _libproc = ctypes.CDLL(ctypes.util.find_library("proc"))
    _libproc.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
    _libproc.proc_name.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    _libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]


def _macos_rusage(pid: int) -> Optional["_RusageInfoV2"]:
    info = _RusageInfoV2()
    if _libproc.proc_pid_rusage(pid, _RUSAGE_INFO_V2, ctypes.byref(info)) != 0:
        return None
    return info


def _macos_processes() -> Dict[int, str]:
    count = _libproc.proc_listallpids(None, 0)
    if count <= 0:
        return {}
    pids = (ctypes.c_int * (count + 64))()
    count = _libproc.proc_listallpids(pids, ctypes.sizeof(pids))
    procs = {}
    name = ctypes.create_string_buffer(256)
    for pid in pids[:max(count, 0)]:
        if pid <= 0:
            continue
        if _libproc.proc_name(pid, name, ctypes.sizeof(name)) > 0:
            procs[pid] = name.value.decode("utf-8", "replace")
    return procs


if _WINDOWS:
    import ctypes
    from ctypes import wintypes

    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _PROCESS_VM_READ = 0x0010
    _IMAGE_PATH_CHARS = 32768

    class _MemoryCountersEx(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t)]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,
                                                  ctypes.POINTER(_MemoryCountersEx),
                                                  wintypes.DWORD]
    _kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    _kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                     ctypes.POINTER(wintypes.DWORD)]


def list_processes() -> Dict[int, str]:
    if _WINDOWS:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                             errors="replace", check=False).stdout
        procs = {}
        for row in csv.reader(io.StringIO(out)):
            if len(row) >= 2 and row[1].isdigit():
                name = row[0][:-4] if row[0].lower().endswith(".exe") else row[0]
                procs[int(row[1])] = name
        return procs
    if _MACOS:
        return _macos_processes()
    procs = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        comm = _proc_text(int(entry.name), "comm")
        if comm is not None:
            procs[int(entry.name)] = comm.strip()
    return procs


def _proc_text(pid: int, name: str) -> Optional[str]:
    try:
        return Path("/proc/{}/{}".format(pid, name)).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _query(pid: int, access: int, read: Callable[[int], Optional[_T]]) -> Optional[_T]:
    handle = _kernel32.OpenProcess(access, False, pid)
    if not handle:
        return None
    try:
        return read(handle)
    finally:
        _kernel32.CloseHandle(handle)


def _image_path(handle: int) -> Optional[str]:
    size = wintypes.DWORD(_IMAGE_PATH_CHARS)
    path = ctypes.create_unicode_buffer(_IMAGE_PATH_CHARS)
    if not _kernel32.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
        return None
    return path.value


def _private_usage(handle: int) -> Optional[int]:
    counters = _MemoryCountersEx()
    counters.cb = ctypes.sizeof(counters)
    if not _kernel32.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return None
    return int(counters.PrivateUsage)


def _creation_time(handle: int) -> Optional[int]:
    times = [wintypes.FILETIME() for _ in range(4)]
    if not _kernel32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
        return None
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def executable_path(pid: int) -> Optional[str]:
    if _WINDOWS:
        return _query(pid, _PROCESS_QUERY_LIMITED_INFORMATION, _image_path)
    if _MACOS:
        path = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
        if _libproc.proc_pidpath(pid, path, ctypes.sizeof(path)) <= 0:
            return None
        return path.value.decode("utf-8", "replace")
    try:
        return os.readlink("/proc/{}/exe".format(pid))
    except OSError:
        return None


def private_bytes(pid: int) -> Optional[int]:
    if _WINDOWS:
        return _query(pid, _PROCESS_QUERY_LIMITED_INFORMATION | _PROCESS_VM_READ, _private_usage)
    if _MACOS:
        info = _macos_rusage(pid)
        return None if info is None else int(info.ri_phys_footprint)
    status = _proc_text(pid, "status")
    if status is None:
        return None
    fields = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        parts = value.split()
        if parts and parts[0].isdigit():
            fields[key] = int(parts[0]) * 1024
    if "RssAnon" not in fields:
        return None
    return fields["RssAnon"] + fields.get("VmSwap", 0)


def start_time(pid: int) -> Optional[int]:
    if _WINDOWS:
        return _query(pid, _PROCESS_QUERY_LIMITED_INFORMATION, _creation_time)
    if _MACOS:
        info = _macos_rusage(pid)
        return None if info is None else int(info.ri_proc_start_abstime)
    stat = _proc_text(pid, "stat")
    if stat is None:
        return None
    return int(stat[stat.rfind(")") + 2:].split()[19])


def kill(pid: int) -> None:
    if _WINDOWS:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, check=False)
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
