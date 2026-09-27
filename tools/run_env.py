"""run_env.py -- Clean stale IDA registry and open a project cmd shell."""

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent

IDA_EXE = Path(r"C:\Program Files\IDA Professional 9.0\ida.exe")
IDA_SCRIPT = PROJECT_DIR / "tools" / "ida_server.py"
REGISTRY_DIR = Path.home() / ".ida-mcp" / "instances"

u32 = ctypes.windll.user32
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

try:
    u32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except Exception:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass


def fail(msg: str):
    print(f"\n  ERROR: {msg}\n")
    input("Press Enter to exit...")
    sys.exit(1)


def launch_all_idas():
    """Clean stale registry JSON files (IDA auto-launch disabled)."""

    # Clean stale registry JSON files
    if REGISTRY_DIR.is_dir():
        for f in REGISTRY_DIR.glob("*.json"):
            print(f"[cleanup] Removing stale registry: {f.name}")
            f.unlink(missing_ok=True)


def run_script(name):
    """Run a sibling script and return its exit code."""
    script = SCRIPT_DIR / name
    print(f"\n[run] Running {name}...")
    result = subprocess.run([sys.executable, str(script)])
    print(f"[run] {name} exited with code {result.returncode}")
    return result.returncode


def main():
    print("=" * 60)
    print("[run_env] Starting IDA environment...")
    print("=" * 60)

    launch_all_idas()

    print(f"\n[cmd] Opening command prompt at {PROJECT_DIR}")
    subprocess.Popen(["cmd", "/k"], cwd=str(PROJECT_DIR),
                     creationflags=subprocess.CREATE_NEW_CONSOLE)

    print("\n[done] Environment ready.")


if __name__ == "__main__":
    main()
