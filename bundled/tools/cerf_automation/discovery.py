from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

STATUS_FILE = "cerf-status.json"
STALE_SECONDS = 7.0
PRODUCT_NAME = "CE Runtime Foundation"
if sys.platform == "win32":
    EXECUTABLE = Path("cerf.exe")
elif sys.platform == "darwin":
    EXECUTABLE = Path(PRODUCT_NAME + ".app", "Contents", "MacOS", PRODUCT_NAME)
else:
    EXECUTABLE = Path("cerf")


def install_and_executable(cerf: Optional[str] = None) -> Tuple[Path, Path]:
    if cerf is None:
        cerf = os.environ.get("CERF_EXE")
    if cerf is None:
        install = Path(__file__).resolve().parents[2]
        path = install / EXECUTABLE
    elif Path(cerf).is_dir():
        install = Path(cerf)
        path = install / EXECUTABLE
    else:
        path = Path(cerf)
        install = path.parents[len(EXECUTABLE.parts) - 1]
    if not path.is_file():
        raise FileNotFoundError(
            "no CE Runtime Foundation executable at {}; pass cerf= or set CERF_EXE".format(path))
    return install, path


def executable(cerf: Optional[str] = None) -> Path:
    return install_and_executable(cerf)[1]


def devices_dir(cerf: Optional[str] = None) -> Path:
    return install_and_executable(cerf)[0] / "devices"


def read_status(device_dir: Path) -> Optional[Dict]:
    try:
        status = json.loads((device_dir / STATUS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if time.time() - float(status.get("heartbeat_unix", 0)) >= STALE_SECONDS:
        return None
    return status


def device_address(device: str, cerf: Optional[str] = None) -> Optional[str]:
    status = read_status(devices_dir(cerf) / device)
    if status is None:
        return None
    return status.get("automation")


def running(cerf: Optional[str] = None) -> List[Dict]:
    found = []
    root = devices_dir(cerf)
    if not root.is_dir():
        return found
    for device_dir in sorted(root.iterdir()):
        status = read_status(device_dir) if device_dir.is_dir() else None
        if status is not None and status.get("automation"):
            found.append({"device": device_dir.name, "pid": status.get("pid"), "address": status["automation"]})
    return found
