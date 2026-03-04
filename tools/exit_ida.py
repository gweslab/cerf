#!/usr/bin/env python3
"""Close all running IDA instances, saving with pack (store).

Finds all ida.exe / ida64.exe windows, sends WM_CLOSE to each,
then handles the "Save database" Qt dialog by pressing Enter
(defaults are already "Pack database (Store)" + "Collect garbage").

IDA uses Qt widgets, not native Win32 controls, so we interact
via keyboard input rather than BM_CLICK messages.
"""

import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
import time

try:
    ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except Exception:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass

u32 = ctypes.windll.user32
k32 = ctypes.windll.kernel32

WM_CLOSE = 0x0010
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
VK_RETURN = 0x0D
KEYEVENTF_KEYUP = 0x0002

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

IDA_PROCESS_NAMES = ["ida.exe", "ida64.exe"]


def find_ida_pids():
    """Find PIDs of all running IDA processes."""
    pids = {}
    for name in IDA_PROCESS_NAMES:
        result = subprocess.run(
            ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
            capture_output=True, text=True,
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line or "No tasks" in line or "INFO" in line:
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                try:
                    pids[int(parts[1].strip('"'))] = name
                except ValueError:
                    pass
    return pids


def get_toplevel_windows(pids):
    """Return list of (hwnd, pid, title) for visible top-level windows."""
    windows = []

    def enum_cb(hwnd, _lparam):
        pid = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in pids and u32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(512)
            u32.GetWindowTextW(hwnd, buf, 512)
            if buf.value:
                windows.append((hwnd, pid.value, buf.value))
        return True

    u32.EnumWindows(WNDENUMPROC(enum_cb), 0)
    return windows


def find_save_dialogs(pids):
    """Find all 'Save database' dialogs for given PIDs."""
    dialogs = []
    for hwnd, pid, title in get_toplevel_windows(pids):
        if "Save database" in title:
            dialogs.append((hwnd, pid, title))
    return dialogs


def wait_for_save_dialog(pid, timeout=5.0):
    """Wait for a 'Save database' dialog for a specific PID."""
    pids = {pid: True}
    deadline = time.time() + timeout
    while time.time() < deadline:
        dialogs = find_save_dialogs(pids)
        if dialogs:
            return dialogs[0][0]
        time.sleep(0.1)
    return None


def press_enter_on(hwnd):
    """Foreground a window and press Enter."""
    u32.SetForegroundWindow(hwnd)
    time.sleep(0.15)
    u32.PostMessageW(hwnd, WM_KEYDOWN, VK_RETURN, 0)
    time.sleep(0.05)
    u32.PostMessageW(hwnd, WM_KEYUP, VK_RETURN, 0)


def wait_pid_exit(pid, timeout=30.0):
    """Wait for a process to exit."""
    handle = k32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        return True
    result = k32.WaitForSingleObject(handle, int(timeout * 1000))
    k32.CloseHandle(handle)
    return result == 0  # WAIT_OBJECT_0


def main():
    pids = find_ida_pids()
    if not pids:
        print("No IDA instances found.")
        return 0

    print(f"Found {len(pids)} IDA instance(s)")

    windows = get_toplevel_windows(pids)
    ida_windows = [(h, p, t) for h, p, t in windows if "IDA -" in t]

    if not ida_windows:
        print("No IDA main windows found.")
        return 0

    for hwnd, pid, title in ida_windows:
        short = title.split("\\")[-1] if "\\" in title else title
        print(f"  [{pid}] {short}")

    # Close one at a time: check for existing dialog -> WM_CLOSE -> wait -> Enter
    for hwnd, pid, title in ida_windows:
        short = title.split("\\")[-1] if "\\" in title else title
        print(f"\nClosing {short} (PID={pid})...")

        # Check if save dialog is already open (e.g. user triggered it)
        existing = find_save_dialogs({pid: True})
        if existing:
            dialog_hwnd = existing[0][0]
            print(f"  Save dialog already open")
        else:
            u32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            dialog_hwnd = wait_for_save_dialog(pid, timeout=5.0)

        if dialog_hwnd:
            # Dialog defaults: "Pack database (Store)" + "Collect garbage"
            # Just press Enter to accept
            press_enter_on(dialog_hwnd)
            print(f"  Enter -> OK (Pack/Store + Collect garbage)")
        else:
            print(f"  No save dialog (closed directly)")

        if wait_pid_exit(pid, timeout=30.0):
            print(f"  Exited.")
        else:
            print(f"  WARNING: still running after 30s")

    # Final check
    time.sleep(0.5)
    remaining = find_ida_pids()
    if remaining:
        print(f"\n{len(remaining)} IDA instance(s) still running.")
        return 1
    else:
        print(f"\nAll IDA instances closed successfully.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
